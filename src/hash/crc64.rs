//! CRC-64 checksums compatible with Go's `hash/crc64` package.

use std::io::{self, Write};

use super::StateError;

/// The CRC-64/ISO reflected polynomial used by HDLC.
pub const ISO: u64 = 0xd800_0000_0000_0000;
/// The CRC-64/ECMA-182 reflected polynomial.
pub const ECMA: u64 = 0xc96c_5795_d787_0f42;
/// The checksum size in bytes.
pub const SIZE: usize = 8;

/// A 256-entry lookup table for a reflected CRC-64 polynomial.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Table([u64; 256]);

impl Table {
    /// Builds a table for `poly`, interpreted as a reflected polynomial as in
    /// Go's `crc64.MakeTable`.
    pub fn new(poly: u64) -> Self {
        let mut values = [0; 256];
        for (i, value) in values.iter_mut().enumerate() {
            let mut crc = i as u64;
            for _ in 0..8 {
                crc = if crc & 1 == 1 {
                    (crc >> 1) ^ poly
                } else {
                    crc >> 1
                };
            }
            *value = crc;
        }
        Self(values)
    }

    /// Builds the predefined CRC-64/ISO table.
    pub fn iso() -> Self {
        Self::new(ISO)
    }

    /// Builds the predefined CRC-64/ECMA table.
    pub fn ecma() -> Self {
        Self::new(ECMA)
    }
}

/// Incremental CRC-64 digest for a selected lookup table.
#[derive(Clone, Debug)]
pub struct Crc64 {
    crc: u64,
    table: Table,
}

impl Crc64 {
    /// Creates a checksum initialized to zero and using a copy of `table`.
    pub fn new(table: &Table) -> Self {
        Self {
            crc: 0,
            table: table.clone(),
        }
    }

    /// Resets the checksum to zero.
    pub fn reset(&mut self) {
        self.crc = 0;
    }

    /// Returns the current checksum.
    pub const fn sum64(&self) -> u64 {
        self.crc
    }

    /// Returns the checksum size in bytes.
    pub const fn size(&self) -> usize {
        SIZE
    }

    /// Returns the CRC block size, which is one byte.
    pub const fn block_size(&self) -> usize {
        1
    }

    /// Adds bytes to the current checksum.
    pub fn update(&mut self, bytes: &[u8]) {
        self.crc = update(self.crc, &self.table, bytes);
    }

    /// Appends the checksum in big-endian order without resetting state.
    pub fn sum(&self, into: &mut Vec<u8>) {
        into.extend_from_slice(&self.crc.to_be_bytes());
    }

    /// Appends the Go-compatible binary state, including its table identity.
    pub fn append_binary(&self, into: &mut Vec<u8>) {
        into.extend_from_slice(b"crc\x02");
        into.extend_from_slice(&table_checksum(&self.table).to_be_bytes());
        into.extend_from_slice(&self.crc.to_be_bytes());
    }

    /// Serializes the current state in Go's `hash/crc64` format.
    pub fn marshal_binary(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(20);
        self.append_binary(&mut bytes);
        bytes
    }

    /// Restores a state only if it was created with a matching CRC table.
    pub fn unmarshal_binary(&mut self, bytes: &[u8]) -> Result<(), StateError> {
        if bytes.len() < 4 || &bytes[..4] != b"crc\x02" {
            return Err(StateError::new("hash/crc64: invalid hash state identifier"));
        }
        if bytes.len() != 20 {
            return Err(StateError::new("hash/crc64: invalid hash state size"));
        }
        if u64::from_be_bytes(bytes[4..12].try_into().expect("fixed state range"))
            != table_checksum(&self.table)
        {
            return Err(StateError::new("hash/crc64: tables do not match"));
        }
        self.crc = u64::from_be_bytes(bytes[12..20].try_into().expect("fixed state range"));
        Ok(())
    }
}

impl Write for Crc64 {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.update(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Returns the result of adding `bytes` to an existing checksum.
pub fn update(mut crc: u64, table: &Table, bytes: &[u8]) -> u64 {
    crc = !crc;
    for &byte in bytes {
        crc = table.0[((crc as u8) ^ byte) as usize] ^ (crc >> 8);
    }
    !crc
}

/// Computes a checksum of `bytes` with the selected table.
pub fn checksum(bytes: &[u8], table: &Table) -> u64 {
    update(0, table, bytes)
}

fn table_checksum(table: &Table) -> u64 {
    let mut bytes = [0u8; 256 * 8];
    for (index, value) in table.0.iter().enumerate() {
        bytes[index * 8..index * 8 + 8].copy_from_slice(&value.to_be_bytes());
    }
    checksum(&bytes, &Table::iso())
}
