//! Append-only, signed, hash-chained logs. Each device writes only its own file, so any
//! transport can copy them without write conflicts.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use aws_lc_rs::signature::Ed25519KeyPair;

use crate::crypto::{self, Hash};
use crate::ids::DeviceId;
use crate::record::Body;
use crate::wire::{Reader, Writer};
use crate::{Error, Result};

const MAGIC: [u8; 2] = *b"LV";
const VERSION: u8 = 1;
const SIGNATURE_LEN: usize = 64;
/// How far ahead of this device another device's clock is believed. Latest write wins, so without
/// this an entry dated far ahead would beat every honest edit, on every device, from then on.
pub const MAX_CLOCK_LEAD_MS: u64 = 24 * 60 * 60 * 1000;
/// Bounds what a hostile peer can make us allocate for one entry.
pub const MAX_BODY: usize = 1 << 24;

/// One signed record. `body` stays encoded until it is applied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub kind: u8,
    pub device: DeviceId,
    pub seq: u64,
    pub clock: u64,
    pub prev: Hash,
    pub body: Vec<u8>,
    pub signature: [u8; SIGNATURE_LEN],
}

impl Entry {
    /// The bytes covered by the signature.
    pub fn signed_bytes(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.array(&MAGIC);
        w.u8(VERSION);
        w.u8(self.kind);
        w.array(self.device.as_bytes());
        w.u64(self.seq);
        w.u64(self.clock);
        w.array(&self.prev);
        w.bytes(&self.body);
        w.finish()
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = self.signed_bytes();
        bytes.extend_from_slice(&self.signature);
        bytes
    }

    pub fn hash(&self) -> Hash {
        crypto::hash(&[&self.encode()])
    }

    fn decode(reader: &mut Reader<'_>) -> Result<Self> {
        if reader.array::<2>()? != MAGIC {
            return Err(Error::Corrupt("not a vault log"));
        }
        if reader.u8()? != VERSION {
            return Err(Error::Newer);
        }
        let kind = reader.u8()?;
        let device = reader.id()?;
        let seq = reader.u64()?;
        let clock = reader.u64()?;
        let prev = reader.array()?;
        // Checked before reading on: a length past the limit is damage, never a write cut short.
        let len = reader.u32()? as usize;
        if len > MAX_BODY {
            return Err(Error::Corrupt("record is too large"));
        }
        let body = reader.take(len)?.to_vec();
        let signature = reader.array()?;
        Ok(Self { kind, device, seq, clock, prev, body, signature })
    }
}

/// What a device's log file holds once parsed.
#[derive(Debug, Default)]
pub struct Parsed {
    pub entries: Vec<Entry>,
    /// Bytes that parse as whole entries.
    pub valid_len: usize,
    /// The bytes after those stop short of a whole entry, which a crash mid-write leaves.
    pub torn: bool,
    /// The bytes after those are not an entry at all, which a crash does not leave.
    pub damaged: bool,
    pub newer: bool,
}

/// Parses until the first entry that cannot be read.
pub fn parse(bytes: &[u8]) -> Parsed {
    let mut parsed = Parsed::default();
    let mut reader = Reader::new(bytes);
    while reader.remaining() > 0 {
        match Entry::decode(&mut reader) {
            Ok(entry) => {
                parsed.entries.push(entry);
                parsed.valid_len = bytes.len() - reader.remaining();
            }
            Err(Error::Newer) => {
                parsed.newer = true;
                break;
            }
            Err(error) => {
                // A crash leaves part of one write at the end and nothing whole after it. A whole
                // entry further on means a changed length byte, and cutting there would lose it.
                parsed.torn = crate::wire::ran_out(&error) && !holds_an_entry(&bytes[parsed.valid_len + 1..]);
                parsed.damaged = !parsed.torn;
                break;
            }
        }
    }
    parsed
}

/// Whether a whole entry starts anywhere in `bytes`. Only a log that stopped parsing is searched.
fn holds_an_entry(bytes: &[u8]) -> bool {
    (0..bytes.len()).any(|at| bytes[at..].starts_with(&MAGIC) && Entry::decode(&mut Reader::new(&bytes[at..])).is_ok())
}

pub fn path_for(home: &Path, device: &DeviceId) -> PathBuf {
    home.join("log").join(format!("{device}.lvl"))
}

pub fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::with_capacity(bytes.len() * 2), |mut out, byte| {
        let _ = write!(out, "{byte:02x}");
        out
    })
}

/// Where a copy of a log goes when a removal settled on another. Something may be built on it.
pub(crate) fn displaced_path(home: &Path, device: &DeviceId) -> PathBuf {
    path_for(home, device).with_extension("displaced")
}

pub(crate) fn device_from_path(path: &Path) -> Option<DeviceId> {
    if path.extension()? != "lvl" {
        return None;
    }
    let stem = path.file_stem()?.to_str()?;
    if stem.len() != 32 || !stem.is_ascii() {
        return None;
    }
    let mut device = [0u8; 16];
    for (byte, pair) in device.iter_mut().zip(stem.as_bytes().chunks(2)) {
        *byte = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
    }
    // One device, one file name. A second spelling would be a second log for the same device.
    (hex(&device) == stem).then(|| device.into())
}

/// This device's own log, open for appending. The file is never ahead of what has been reported as
/// written, or a later entry would reuse a sequence number and vanish at the next start.
#[derive(Debug)]
pub struct Appender {
    file: File,
    len: u64,
    entries: u64,
    /// A write failed and could not be taken back, so nothing else may go after it.
    stuck: bool,
    #[cfg(test)]
    pub fail_next_write: bool,
}

impl Appender {
    /// Opens the log, keeping a copy of any torn tail beside it. Anything else unreadable stops
    /// here: what lies behind damage may be real entries, and only a person can decide about them.
    pub fn open(path: &Path) -> Result<Self> {
        let bytes = match fs::read(path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(error) => return Err(error.into()),
        };
        let parsed = parse(&bytes);
        if parsed.damaged {
            return Err(Error::Corrupt("this device's log has damage in it. Recover from another device or a backup"));
        }
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        if parsed.torn {
            // Only this device writes this file, so a torn tail is our own interrupted write. A
            // changed length byte looks the same, so what is cut stays on disk.
            let kept = path.with_extension(format!("{}.torn", hex(&crypto::random::<4>())));
            fs::write(kept, &bytes[parsed.valid_len..])?;
            file.set_len(parsed.valid_len as u64)?;
        }
        let (len, entries) = (parsed.valid_len as u64, parsed.entries.len() as u64);
        Ok(Self {
            file,
            len,
            entries,
            stuck: false,
            #[cfg(test)]
            fail_next_write: false,
        })
    }

    /// How many entries the file holds.
    pub fn entries(&self) -> u64 {
        self.entries
    }

    fn write(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        #[cfg(test)]
        if std::mem::take(&mut self.fail_next_write) {
            self.file.write_all(&bytes[..bytes.len() / 2])?;
            return Err(std::io::Error::other("the disk is full"));
        }
        self.file.write_all(bytes)?;
        self.file.sync_data()
    }

    /// Writes entries in one call and returns once they are durable. If that fails, the file goes
    /// back to where it was.
    pub fn append_all(&mut self, entries: &[Entry]) -> Result<()> {
        if self.stuck {
            return Err(Error::Corrupt("an earlier write failed, so nothing else can be saved. Restart to try again"));
        }
        let bytes: Vec<u8> = entries.iter().flat_map(Entry::encode).collect();
        if let Err(error) = self.write(&bytes) {
            self.stuck = self.file.set_len(self.len).and_then(|()| self.file.sync_data()).is_err();
            return Err(error.into());
        }
        self.len += bytes.len() as u64;
        self.entries += entries.len() as u64;
        Ok(())
    }
}

/// The head of one device's log. Every entry anywhere is made by `next`, so nothing else has to
/// know how an entry is linked or signed.
#[derive(Debug)]
pub struct Chain {
    pub device: DeviceId,
    pub seq: u64,
    pub prev: Hash,
}

impl Chain {
    pub fn next(&mut self, clock: u64, body: &Body, key: &Ed25519KeyPair) -> Entry {
        let mut entry = Entry {
            kind: body.kind(),
            device: self.device,
            seq: self.seq,
            clock,
            prev: self.prev,
            body: body.encode(),
            signature: [0; SIGNATURE_LEN],
        };
        entry.signature = key.sign(&entry.signed_bytes()).as_ref().try_into().expect("Ed25519 signatures are 64 bytes");
        self.seq += 1;
        self.prev = entry.hash();
        entry
    }
}

/// A hybrid logical clock: wall time in the high bits, a counter in the low 16. It never moves
/// backwards and never falls behind anything seen, so causal order survives skewed clocks.
#[derive(Debug, Default, Clone, Copy)]
pub struct Clock(u64);

impl Clock {
    pub fn observe(&mut self, seen: u64) {
        self.0 = self.0.max(seen);
    }

    pub fn tick(&mut self, now_ms: u64) -> u64 {
        self.0 = (now_ms << 16).max(self.0.saturating_add(1));
        self.0
    }
}

/// The wall time a clock reading was taken at.
pub fn wall_ms(clock: u64) -> u64 {
    clock >> 16
}

/// Whether a clock from another device could be true, given this one's.
pub fn is_plausible(clock: u64, now_ms: u64) -> bool {
    wall_ms(clock) <= now_ms.saturating_add(MAX_CLOCK_LEAD_MS)
}

pub fn now_ms() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |elapsed| u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(seq: u64) -> Entry {
        Entry { kind: 7, device: [1; 16].into(), seq, clock: seq, prev: [2; 32], body: vec![3; 40], signature: [4; 64] }
    }

    #[test]
    fn a_log_file_has_one_name() {
        let device = DeviceId::from([0xab; 16]);
        let canonical = path_for(Path::new("/"), &device);
        assert_eq!(device_from_path(&canonical), Some(device));
        let other = canonical.to_string_lossy().replace("ab", "AB");
        assert_eq!(device_from_path(Path::new(&other)), None, "two files must not claim one device");
        let signed = format!("/log/+{}.lvl", "f".repeat(31));
        assert_eq!(device_from_path(Path::new(&signed)), None);
    }

    #[test]
    fn entries_round_trip() {
        let bytes: Vec<u8> = [entry(0), entry(1)].iter().flat_map(Entry::encode).collect();
        let parsed = parse(&bytes);
        assert_eq!(parsed.entries, [entry(0), entry(1)]);
        assert!(!parsed.torn);
    }

    #[test]
    fn a_torn_tail_keeps_every_whole_entry() {
        let mut bytes = entry(0).encode();
        let whole = bytes.len();
        bytes.extend_from_slice(&entry(1).encode()[..50]);
        let parsed = parse(&bytes);
        assert_eq!(parsed.entries.len(), 1);
        assert_eq!(parsed.valid_len, whole);
        assert!(parsed.torn);
    }

    #[test]
    fn appender_repairs_a_torn_tail() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("own.lvl");
        let mut bytes = entry(0).encode();
        bytes.extend_from_slice(&entry(1).encode()[..9]);
        fs::write(&path, bytes).unwrap();

        Appender::open(&path).unwrap().append_all(&[entry(1)]).unwrap();

        let parsed = parse(&fs::read(&path).unwrap());
        assert_eq!(parsed.entries, [entry(0), entry(1)]);
        assert!(!parsed.torn);
    }

    #[test]
    fn an_unreadable_entry_with_more_behind_it_is_damage_not_a_torn_tail() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("own.lvl");
        let (first, second, third) = (entry(0).encode(), entry(1).encode(), entry(2).encode());
        let mut bytes = [first.clone(), second, third].concat();
        // One flipped byte in the middle of the file, in a magic number.
        bytes[first.len()] ^= 0xff;
        fs::write(&path, &bytes).unwrap();

        assert!(parse(&bytes).damaged, "this is not a crash mid-write");
        assert!(Appender::open(&path).is_err(), "opening must not destroy what is behind the damage");
        assert_eq!(fs::read(&path).unwrap(), bytes, "the file must be left as it was");
    }

    #[test]
    fn a_changed_length_byte_is_damage_not_a_torn_tail() {
        let (first, second, third) = (entry(0).encode(), entry(1).encode(), entry(2).encode());
        // The second entry's body length sits after its 68-byte header, little-endian.
        let length = first.len() + 68;
        for (byte, flip) in [(length + 3, 0x80), (length, 0x40)] {
            let mut bytes = [first.clone(), second.clone(), third.clone()].concat();
            bytes[byte] ^= flip;
            let parsed = parse(&bytes);
            assert!(parsed.damaged && !parsed.torn, "a later whole entry must not be cut as a torn write");
        }
    }

    #[test]
    fn a_torn_tail_is_kept_beside_the_log_before_it_is_cut() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("own.lvl");
        let mut bytes = entry(0).encode();
        let whole = bytes.len();
        bytes.extend_from_slice(&entry(1).encode()[..50]);
        fs::write(&path, &bytes).unwrap();
        Appender::open(&path).unwrap();
        assert_eq!(fs::read(&path).unwrap().len(), whole);
        let kept: Vec<_> = fs::read_dir(dir.path()).unwrap().flatten().filter(|file| file.file_name().to_string_lossy().contains("torn")).collect();
        assert_eq!(kept.len(), 1, "what was cut must still exist");
    }

    #[test]
    fn a_failed_write_leaves_the_file_where_it_was_or_stops_all_further_writes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("own.lvl");
        let mut appender = Appender::open(&path).unwrap();
        appender.append_all(&[entry(0)]).unwrap();
        let before = fs::read(&path).unwrap();

        // A write that cannot complete, as on a full disk.
        appender.fail_next_write = true;
        assert!(appender.append_all(&[entry(1)]).is_err());
        assert_eq!(fs::read(&path).unwrap(), before, "a failed append must not leave part of itself");
        appender.append_all(&[entry(1)]).unwrap();
        assert_eq!(parse(&fs::read(&path).unwrap()).entries.len(), 2);
    }

    #[test]
    fn a_future_version_is_reported_rather_than_treated_as_damage() {
        let mut bytes = entry(0).encode();
        bytes[2] = VERSION + 1;
        assert!(parse(&bytes).newer);
    }

    #[test]
    fn a_clock_at_the_end_of_its_range_stops_rather_than_wrapping() {
        let mut clock = Clock::default();
        clock.observe(u64::MAX);
        assert_eq!(clock.tick(1), u64::MAX, "a wrapped clock would go backwards and break this device's own chain");
    }

    #[test]
    fn a_clock_is_believed_only_so_far_ahead_of_this_one() {
        let now = 1_000_000;
        assert!(is_plausible(now << 16, now));
        assert!(is_plausible(((now + MAX_CLOCK_LEAD_MS) << 16) + 0xffff, now));
        assert!(!is_plausible((now + MAX_CLOCK_LEAD_MS + 1) << 16, now));
        assert!(!is_plausible(u64::MAX, now));
    }

    #[test]
    fn clock_stays_ahead_of_everything_it_saw_even_when_wall_time_is_behind() {
        let mut clock = Clock::default();
        clock.observe(1_000 << 16);
        let first = clock.tick(1);
        let second = clock.tick(1);
        assert!(first > 1_000 << 16);
        assert!(second > first);
    }
}
