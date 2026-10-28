//! CRC-32 checksums compatible with Go's `hash/crc32` package.

use std::io::{self, Write};

use super::StateError;

/// The CRC-32/IEEE reflected polynomial.
pub const IEEE: u32 = 0xedb8_8320;
/// The CRC-32/Castagnoli reflected polynomial.
pub const CASTAGNOLI: u32 = 0x82f6_3b78;
/// The CRC-32/Koopman reflected polynomial.
pub const KOOPMAN: u32 = 0xeb31_d82e;
/// The checksum size in bytes.
pub const SIZE: usize = 4;

/// A 256-entry lookup table for a reflected CRC-32 polynomial.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Table([u32; 256]);

impl Table {
    /// Builds a table for `poly`, interpreted as a reflected polynomial as in
    /// Go's `crc32.MakeTable`.
    pub const fn new(poly: u32) -> Self {
        let mut values = [0; 256];
        let mut i = 0;
        while i < 256 {
            let mut crc = i as u32;
            let mut bit = 0;
            while bit < 8 {
                crc = if crc & 1 == 1 {
                    (crc >> 1) ^ poly
                } else {
                    crc >> 1
                };
                bit += 1;
            }
            values[i] = crc;
            i += 1;
        }
        Self(values)
    }

    /// The shared table for the CRC-32/IEEE polynomial (Go's `IEEETable`).
    pub fn ieee() -> &'static Table {
        static IEEE_TABLE: Table = Table::new(IEEE);
        &IEEE_TABLE
    }

    /// Builds a table for the CRC-32/Castagnoli polynomial.
    pub fn castagnoli() -> Self {
        Self::new(CASTAGNOLI)
    }

    /// Builds a table for the CRC-32/Koopman polynomial.
    pub fn koopman() -> Self {
        Self::new(KOOPMAN)
    }
}

/// Incremental CRC-32 digest for a selected lookup table.
#[derive(Clone, Debug)]
pub struct Crc32 {
    crc: u32,
    table: Table,
}

impl Crc32 {
    /// Creates a checksum initialized to zero and using a copy of `table`.
    pub fn new(table: &Table) -> Self {
        Self {
            crc: 0,
            table: table.clone(),
        }
    }

    /// Creates a checksum using the standard IEEE polynomial.
    pub fn ieee() -> Self {
        Self::new(Table::ieee())
    }

    /// Resets the checksum to zero.
    pub fn reset(&mut self) {
        self.crc = 0;
    }

    /// Returns the current checksum.
    pub const fn sum32(&self) -> u32 {
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
        into.extend_from_slice(b"crc\x01");
        into.extend_from_slice(&table_checksum(&self.table).to_be_bytes());
        into.extend_from_slice(&self.crc.to_be_bytes());
    }

    /// Serializes the current state in Go's `hash/crc32` format.
    pub fn marshal_binary(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(12);
        self.append_binary(&mut bytes);
        bytes
    }

    /// Restores a state only if it was created with a matching CRC table.
    pub fn unmarshal_binary(&mut self, bytes: &[u8]) -> Result<(), StateError> {
        if bytes.len() < 4 || &bytes[..4] != b"crc\x01" {
            return Err(StateError::new("hash/crc32: invalid hash state identifier"));
        }
        if bytes.len() != 12 {
            return Err(StateError::new("hash/crc32: invalid hash state size"));
        }
        if u32::from_be_bytes(bytes[4..8].try_into().expect("fixed state range"))
            != table_checksum(&self.table)
        {
            return Err(StateError::new("hash/crc32: tables do not match"));
        }
        self.crc = u32::from_be_bytes(bytes[8..12].try_into().expect("fixed state range"));
        Ok(())
    }
}

impl Write for Crc32 {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.update(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Returns the result of adding `bytes` to an existing checksum.
pub fn update(mut crc: u32, table: &Table, bytes: &[u8]) -> u32 {
    crc = !crc;
    for &byte in bytes {
        crc = table.0[((crc as u8) ^ byte) as usize] ^ (crc >> 8);
    }
    !crc
}

/// Computes a checksum of `bytes` with the selected table.
pub fn checksum(bytes: &[u8], table: &Table) -> u32 {
    update(0, table, bytes)
}

/// Computes a CRC-32/IEEE checksum.
pub fn checksum_ieee(bytes: &[u8]) -> u32 {
    checksum(bytes, Table::ieee())
}

fn table_checksum(table: &Table) -> u32 {
    let mut bytes = [0u8; 256 * 4];
    for (index, value) in table.0.iter().enumerate() {
        bytes[index * 4..index * 4 + 4].copy_from_slice(&value.to_be_bytes());
    }
    checksum_ieee(&bytes)
}
