//! Two devices bringing each other up to date. Each says how much of every log it holds, then
//! sends only what the other lacks.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use crate::crypto::{self, Hash};
use crate::ids::DeviceId;
use crate::net::channel::{Channel, MAX_LOGS};
use crate::store::{self, Logs};
use crate::wire::{Reader, Writer};
use crate::{Error, Result};

/// Thousands of devices, far past what any vault holds.
const MAX_LENGTHS: usize = 1 << 21;

/// Each log's length and hash. Lengths alone would never show two histories of the same length.
fn encode_lengths(logs: &Logs) -> Vec<u8> {
    let mut w = Writer::new();
    for (device, bytes) in logs {
        w.array(device.as_bytes());
        w.u64(bytes.len() as u64);
        w.array(&crypto::hash(&[bytes]));
    }
    w.finish()
}

pub(crate) fn decode_lengths(bytes: &[u8]) -> Result<BTreeMap<DeviceId, (u64, Hash)>> {
    let mut r = Reader::new(bytes);
    let mut lengths = BTreeMap::new();
    while r.remaining() > 0 {
        let device = r.id()?;
        lengths.insert(device, (r.u64()?, r.array()?));
    }
    Ok(lengths)
}

/// Everything the other side lacks, given what it holds. A log it holds differently goes whole, so
/// the comparison on its side finds the contradiction and reports it.
fn encode_tails(logs: &Logs, theirs: &BTreeMap<DeviceId, (u64, Hash)>) -> Vec<u8> {
    let mut w = Writer::new();
    for (device, bytes) in logs {
        let (held, hash) = theirs.get(device).copied().unwrap_or((0, crypto::hash(&[b""])));
        let Ok(offset) = usize::try_from(held) else { continue };
        let same = bytes.get(..offset).is_some_and(|prefix| crypto::hash(&[prefix]) == hash);
        let from = if same { offset } else { 0 };
        if from < bytes.len() && (same || offset <= bytes.len()) {
            w.array(device.as_bytes());
            w.u64(from as u64);
            w.bytes(&bytes[from..]);
        }
    }
    w.finish()
}

/// Rebuilds whole logs from tails. Whether they are acceptable is for `merge_logs` to decide.
pub(crate) fn decode_tails(bytes: &[u8], logs: &Logs) -> Result<Logs> {
    let mut r = Reader::new(bytes);
    let mut whole = Logs::new();
    let mut seen = BTreeSet::new();
    while r.remaining() > 0 {
        let device: DeviceId = r.id()?;
        let offset = usize::try_from(r.u64()?).unwrap_or(usize::MAX);
        let tail = r.bytes()?;
        // Each tail copies the whole of a log, so a short message saying one over and over could
        // ask for any amount of memory.
        if !seen.insert(device) {
            return Err(Error::Peer("the other device sent a log twice"));
        }
        let ours = logs.get(&device).map_or(&[][..], Vec::as_slice);
        if let Some(head) = ours.get(..offset) {
            whole.insert(device, [head, tail].concat());
        }
    }
    Ok(whole)
}

/// The side that connected. Taking turns means neither can block the other on a full socket.
pub(crate) fn initiate(channel: &mut Channel, home: &Path) -> Result<Logs> {
    let logs = store::read_logs(home)?;
    channel.send(&encode_lengths(&logs))?;
    let theirs = decode_lengths(&channel.recv(MAX_LENGTHS)?)?;
    let incoming = decode_tails(&channel.recv(MAX_LOGS)?, &logs)?;
    channel.send(&encode_tails(&logs, &theirs))?;
    Ok(incoming)
}

pub(crate) fn respond(channel: &mut Channel, home: &Path) -> Result<Logs> {
    let logs = store::read_logs(home)?;
    let theirs = decode_lengths(&channel.recv(MAX_LENGTHS)?)?;
    channel.send(&encode_lengths(&logs))?;
    channel.send(&encode_tails(&logs, &theirs))?;
    decode_tails(&channel.recv(MAX_LOGS)?, &logs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_missing_bytes_are_sent_and_logs_rebuild_whole() {
        let device = DeviceId::from([1; 16]);
        let full = BTreeMap::from([(device, vec![1, 2, 3, 4, 5])]);
        let partial = BTreeMap::from([(device, vec![1, 2])]);

        let lengths = decode_lengths(&encode_lengths(&partial)).unwrap();
        let tails = encode_tails(&full, &lengths);
        assert!(tails.len() < 16 + 8 + 4 + 5, "must not resend what the other side holds");
        assert_eq!(decode_tails(&tails, &partial).unwrap(), Logs::from([(device, vec![1, 2, 3, 4, 5])]));
    }

    #[test]
    fn nothing_is_sent_to_a_side_that_is_level_or_ahead() {
        let device = DeviceId::from([1; 16]);
        let logs = BTreeMap::from([(device, vec![1, 2])]);
        assert_eq!(encode_tails(&logs, &BTreeMap::from([(device, (2, crypto::hash(&[&[1u8, 2]])))])), Vec::<u8>::new());
        assert_eq!(encode_tails(&logs, &BTreeMap::from([(device, (9, [0; 32]))])), Vec::<u8>::new(), "it holds more, so nothing here helps");
    }

    #[test]
    fn a_tail_past_what_is_held_here_is_dropped() {
        let device = DeviceId::from([1; 16]);
        let full = BTreeMap::from([(device, vec![1, 2, 3, 4, 5])]);
        let tails = encode_tails(&full, &BTreeMap::from([(device, (3, crypto::hash(&[&[1u8, 2, 3]])))]));
        assert_eq!(decode_tails(&tails, &BTreeMap::new()).unwrap(), Logs::new());
    }

    #[test]
    fn two_histories_of_the_same_length_are_not_mistaken_for_one() {
        let device = DeviceId::from([1; 16]);
        let (mine, theirs) = (BTreeMap::from([(device, vec![1, 2, 3])]), BTreeMap::from([(device, vec![1, 2, 9])]));
        let tails = encode_tails(&mine, &decode_lengths(&encode_lengths(&theirs)).unwrap());
        assert_eq!(
            decode_tails(&tails, &theirs).unwrap(),
            Logs::from([(device, vec![1, 2, 3])]),
            "the whole log goes, so the other side can see the fork"
        );
    }

    #[test]
    fn a_log_sent_twice_is_refused_before_it_costs_anything() {
        let device = DeviceId::from([1; 16]);
        let logs = BTreeMap::from([(device, vec![7; 1000])]);
        let mut w = Writer::new();
        for _ in 0..2 {
            w.array(device.as_bytes());
            w.u64(1000);
            w.bytes(&[]);
        }
        assert!(decode_tails(&w.finish(), &logs).is_err());
    }

    #[test]
    fn truncated_messages_are_refused_without_panicking() {
        let device = DeviceId::from([1; 16]);
        let full = BTreeMap::from([(device, vec![1, 2, 3])]);
        let bytes = encode_tails(&full, &BTreeMap::new());
        for length in 1..bytes.len() {
            assert!(decode_tails(&bytes[..length], &full).is_err());
        }
    }
}
