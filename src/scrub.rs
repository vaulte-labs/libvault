//! Removes secret values from a stream of bytes, including values split across chunks.

use zeroize::Zeroize;

pub(crate) const REPLACEMENT: &[u8] = b"[hidden by vlt]";

#[derive(Debug, Default)]
pub struct Scrubber {
    secrets: Vec<Vec<u8>>,
    held: Vec<u8>,
}

impl Drop for Scrubber {
    fn drop(&mut self) {
        self.secrets.zeroize();
        self.held.zeroize();
    }
}

impl Scrubber {
    pub fn new<S: AsRef<[u8]>>(secrets: impl IntoIterator<Item = S>) -> Self {
        let mut secrets: Vec<Vec<u8>> = secrets.into_iter().map(|secret| secret.as_ref().to_vec()).filter(|secret| !secret.is_empty()).collect();
        // Longest first, so a secret containing another is hidden whole.
        secrets.sort_by_key(|secret| std::cmp::Reverse(secret.len()));
        Self { secrets, held: Vec::new() }
    }

    /// Takes the next chunk and returns what is safe to pass on. Holds back only bytes that could
    /// be the start of a secret, so streamed output is not delayed by a fixed window.
    pub fn push(&mut self, chunk: &[u8]) -> Vec<u8> {
        self.held.extend_from_slice(chunk);
        let (out, used) = self.scan(false);
        self.held.drain(..used);
        out
    }

    /// Returns whatever was held back, at the end of the stream.
    pub fn finish(&mut self) -> Vec<u8> {
        let (out, _) = self.scan(true);
        self.held.clear();
        out
    }

    /// Goes through `held` from the start. Only the position being read decides, so a byte that
    /// could begin one secret cannot split up a secret that is already whole in front of it.
    fn scan(&self, ended: bool) -> (Vec<u8>, usize) {
        let mut out = Vec::with_capacity(self.held.len());
        let mut used = 0;
        while used < self.held.len() {
            let rest = &self.held[used..];
            // The rest of the stream could still complete a longer secret than any here so far.
            if !ended && self.secrets.iter().any(|secret| secret.len() > rest.len() && secret.starts_with(rest)) {
                break;
            }
            if let Some(secret) = self.secrets.iter().find(|secret| rest.starts_with(secret)) {
                out.extend_from_slice(REPLACEMENT);
                used += secret.len();
            } else {
                out.push(rest[0]);
                used += 1;
            }
        }
        (out, used)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(secrets: &[&str], chunks: &[&str]) -> String {
        let mut scrubber = Scrubber::new(secrets);
        let mut out = Vec::new();
        for chunk in chunks {
            out.extend(scrubber.push(chunk.as_bytes()));
        }
        out.extend(scrubber.finish());
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn hides_a_secret_inside_a_chunk() {
        assert_eq!(run(&["sk-123"], &["key is sk-123 ok"]), "key is [hidden by vlt] ok");
    }

    #[test]
    fn hides_a_secret_split_at_every_possible_boundary() {
        let text = "before sk-secret-value after";
        for split in 0..=text.len() {
            let (first, second) = text.split_at(split);
            assert_eq!(run(&["sk-secret-value"], &[first, second]), "before [hidden by vlt] after", "split at {split}");
        }
    }

    #[test]
    fn hides_a_secret_arriving_one_byte_at_a_time() {
        let text = "a sk-123 b sk-123 c";
        let chunks: Vec<String> = text.chars().map(String::from).collect();
        let chunks: Vec<&str> = chunks.iter().map(String::as_str).collect();
        assert_eq!(run(&["sk-123"], &chunks), "a [hidden by vlt] b [hidden by vlt] c");
    }

    #[test]
    fn the_longer_of_two_overlapping_secrets_wins() {
        assert_eq!(run(&["abc", "abcdef"], &["xabcdefy"]), "x[hidden by vlt]y");
    }

    #[test]
    fn a_secret_that_ends_with_its_first_byte_is_hidden_at_the_end_of_a_chunk() {
        assert_eq!(run(&["kAUDITLEAKk"], &["value=kAUDITLEAKk"]), "value=[hidden by vlt]");
        assert_eq!(run(&["kAUDITLEAKk"], &["value=kAUDITLEAKk", " more"]), "value=[hidden by vlt] more");
    }

    #[test]
    fn a_secret_whose_end_starts_it_again_is_hidden_wherever_a_chunk_ends() {
        let text = "x abcabcabc y";
        for split in 0..=text.len() {
            let (first, second) = text.split_at(split);
            assert_eq!(run(&["abcabc"], &[first, second]), "x [hidden by vlt]abc y", "split at {split}");
        }
    }

    #[test]
    fn a_shorter_secret_waits_to_see_whether_a_longer_one_is_coming() {
        assert_eq!(run(&["abc", "abcdef"], &["xabc", "defy"]), "x[hidden by vlt]y");
        assert_eq!(run(&["abc", "abcdef"], &["xabc", "dey"]), "x[hidden by vlt]dey");
    }

    #[test]
    fn a_near_miss_is_passed_through_at_the_end_of_the_stream() {
        assert_eq!(run(&["sk-123"], &["ends with sk-12"]), "ends with sk-12");
    }

    #[test]
    fn ordinary_text_is_not_held_back() {
        let mut scrubber = Scrubber::new(["sk-123"]);
        assert_eq!(scrubber.push(b"data: hello\n"), b"data: hello\n");
    }

    #[test]
    fn a_whole_secret_is_replaced_without_waiting_for_more() {
        let mut scrubber = Scrubber::new(["secret"]);
        assert_eq!(scrubber.push(b"secret"), REPLACEMENT);
    }

    #[test]
    fn the_marker_beside_bytes_that_spell_a_short_secret_is_not_the_secret() {
        // From the fuzzer: the secret is `]` and 0x02, split across chunks. It is hidden, and the
        // marker's own last `]` then sits before a real 0x02.
        let mut scrubber = Scrubber::new([b"]\x02"]);
        let mut out = scrubber.push(b"\x02]");
        out.extend(scrubber.push(b"\x02\x02"));
        out.extend(scrubber.finish());
        assert_eq!(out, [b"\x02".as_slice(), REPLACEMENT, b"\x02"].concat());
    }

    #[test]
    fn with_no_secrets_everything_passes() {
        assert_eq!(run(&[], &["plain"]), "plain");
    }
}
