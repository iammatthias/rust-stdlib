//! Bounded in-memory archive interchange and Go-shaped `archive/tar` and
//! `archive/zip` readers and writers. No filesystem extraction is performed.
pub mod iofs;
pub mod tar;
pub mod zip;
