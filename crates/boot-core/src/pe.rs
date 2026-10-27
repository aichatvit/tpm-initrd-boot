//! Narrow Authenticode SHA-256 reader for this project's unsigned PE32+ loader.
//! Rejects certificate tables, excessive sections, gaps, overlap and truncated headers.
use crate::{Error, Result};
use alloc::vec::Vec;
use sha2::{Digest, Sha256};
fn u16le(b: &[u8], p: usize) -> Result<u16> {
    Ok(u16::from_le_bytes(
        b.get(p..p + 2).ok_or(Error::Bounds)?.try_into().unwrap(),
    ))
}
fn u32le(b: &[u8], p: usize) -> Result<usize> {
    Ok(u32::from_le_bytes(b.get(p..p + 4).ok_or(Error::Bounds)?.try_into().unwrap()) as usize)
}
pub fn unsigned_efi_digest(b: &[u8]) -> Result<[u8; 32]> {
    if b.get(..2) != Some(b"MZ") {
        return Err(Error::InvalidFormat);
    }
    let pe = u32le(b, 0x3c)?;
    // File size is bounded by the EFI caller; checked arithmetic still avoids parser overflow.
    let opt = pe.checked_add(24).ok_or(Error::Bounds)?;
    if b.get(pe..opt - 20) != Some(b"PE\0\0") || u16le(b, pe + 4)? != 0x8664 {
        return Err(Error::InvalidFormat);
    }
    let count = u16le(b, pe + 6)? as usize;
    let opt_size = u16le(b, pe + 20)? as usize;
    if count == 0
        || count > 96
        || opt_size < 152
        || u16le(b, opt)? != 0x20b
        || u32le(b, opt + 108)? < 5
    {
        return Err(Error::InvalidFormat);
    }
    if u16le(b, opt + 68)? != 10 {
        return Err(Error::InvalidFormat);
    } // EFI application
    let headers = u32le(b, opt + 60)?;
    let table = opt.checked_add(opt_size).ok_or(Error::Bounds)?;
    let table_end = table.checked_add(count * 40).ok_or(Error::Bounds)?;
    if headers < table_end || headers > b.len() {
        return Err(Error::Bounds);
    }
    let checksum = opt + 64;
    let cert = opt + 144;
    if u32le(b, cert)? != 0 || u32le(b, cert + 4)? != 0 {
        return Err(Error::InvalidFormat);
    }
    let mut sections = Vec::new();
    for i in 0..count {
        let p = table + i * 40;
        let size = u32le(b, p + 16)?;
        let offset = u32le(b, p + 20)?;
        if size != 0 {
            sections.push((offset, size));
        }
    }
    sections.sort_unstable();
    let mut h = Sha256::new();
    h.update(&b[..checksum]);
    h.update(&b[checksum + 4..cert]);
    h.update(&b[cert + 8..headers]);
    let mut end = headers;
    for (offset, size) in sections {
        if offset != end {
            return Err(Error::InvalidFormat);
        }
        end = offset.checked_add(size).ok_or(Error::Bounds)?;
        h.update(b.get(offset..end).ok_or(Error::Bounds)?);
    }
    h.update(b.get(end..).ok_or(Error::Bounds)?);
    Ok(h.finalize().into())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn malformed_pe_never_panics() {
        for n in 0..2048 {
            let mut b = alloc::vec![0;n];
            if n >= 2 {
                b[..2].copy_from_slice(b"MZ");
            }
            assert!(unsigned_efi_digest(&b).is_err());
        }
        let mut b = alloc::vec![0;256];
        b[..2].copy_from_slice(b"MZ");
        b[0x3c..0x40].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(unsigned_efi_digest(&b).is_err());
    }
}
