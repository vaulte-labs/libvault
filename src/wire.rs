//! Bounds-checked binary encoding for signed records. Hand-written so the bytes that get
//! signed are canonical by construction, with no serializer in the way.

use crate::ids::Generation;
use crate::{Error, Result};

const TOO_SHORT: &str = "record is too short";

/// Whether reading failed by running out of bytes, rather than on something unreadable.
pub fn ran_out(error: &Error) -> bool {
    matches!(error, Error::Corrupt(reason) if *reason == TOO_SHORT)
}

#[derive(Debug, Default)]
pub struct Writer(Vec<u8>);

impl Writer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn u8(&mut self, value: u8) {
        self.0.push(value);
    }

    pub fn u32(&mut self, value: u32) {
        self.0.extend_from_slice(&value.to_le_bytes());
    }

    pub fn u64(&mut self, value: u64) {
        self.0.extend_from_slice(&value.to_le_bytes());
    }

    pub fn generation(&mut self, value: Generation) {
        self.u32(value.number);
        self.array(value.author.as_bytes());
    }

    pub fn array(&mut self, value: &[u8]) {
        self.0.extend_from_slice(value);
    }

    /// Length-prefixed bytes. Lengths fit in u32 because every record is size-limited.
    pub fn bytes(&mut self, value: &[u8]) {
        self.u32(u32::try_from(value.len()).expect("record field exceeds 4 GiB"));
        self.0.extend_from_slice(value);
    }

    pub fn finish(self) -> Vec<u8> {
        self.0
    }
}

#[derive(Debug)]
pub struct Reader<'a> {
    buffer: &'a [u8],
}

impl<'a> Reader<'a> {
    pub fn new(buffer: &'a [u8]) -> Self {
        Self { buffer }
    }

    pub fn remaining(&self) -> usize {
        self.buffer.len()
    }

    pub fn take(&mut self, len: usize) -> Result<&'a [u8]> {
        if len > self.buffer.len() {
            return Err(Error::Corrupt(TOO_SHORT));
        }
        let (head, tail) = self.buffer.split_at(len);
        self.buffer = tail;
        Ok(head)
    }

    pub fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        self.take(N)?.try_into().map_err(|_| Error::Corrupt(TOO_SHORT))
    }

    pub fn id<T: From<[u8; 16]>>(&mut self) -> Result<T> {
        Ok(self.array::<16>()?.into())
    }

    pub fn generation(&mut self) -> Result<Generation> {
        Ok(Generation { number: self.u32()?, author: self.id()? })
    }

    pub fn u8(&mut self) -> Result<u8> {
        Ok(self.array::<1>()?[0])
    }

    pub fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.array()?))
    }

    pub fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.array()?))
    }

    pub fn bytes(&mut self) -> Result<&'a [u8]> {
        let len = self.u32()? as usize;
        self.take(len)
    }

    /// Rejects trailing bytes, so one record has exactly one encoding.
    pub fn finish(self) -> Result<()> {
        if self.buffer.is_empty() { Ok(()) } else { Err(Error::Corrupt("record has trailing bytes")) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_length_prefix_cannot_read_past_the_buffer() {
        let mut bytes = u32::MAX.to_le_bytes().to_vec();
        bytes.extend_from_slice(b"short");
        assert!(Reader::new(&bytes).bytes().is_err());
    }

    #[test]
    fn trailing_bytes_are_rejected() {
        let mut reader = Reader::new(&[1, 2]);
        reader.u8().unwrap();
        assert!(reader.finish().is_err());
    }
}
