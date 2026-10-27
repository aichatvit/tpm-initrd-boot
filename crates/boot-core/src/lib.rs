#![no_std]
extern crate alloc;

pub mod cpio;
pub mod format;
pub mod pe;
pub mod tpm;

use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    InvalidFormat,
    Bounds,
    Signature,
    Mismatch,
    Transport,
    Tpm(u32),
}
pub type Result<T> = core::result::Result<T, Error>;

pub fn hash(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}
