//! Only emits a fixed set of newc entries; never parses untrusted archives.
use crate::{Error, Result};
use alloc::{format, vec::Vec};

fn pad(out: &mut Vec<u8>) {
    while !out.len().is_multiple_of(4) {
        out.push(0);
    }
}
fn entry(out: &mut Vec<u8>, name: &str, data: &[u8], mode: u32, ino: u32) -> Result<()> {
    let size = u32::try_from(data.len()).map_err(|_| Error::Bounds)?;
    let ns = u32::try_from(name.len() + 1).map_err(|_| Error::Bounds)?;
    pad(out);
    let h = format!(
        "070701{ino:08x}{mode:08x}{:08x}{:08x}{:08x}{:08x}{size:08x}{:08x}{:08x}{:08x}{:08x}{ns:08x}{:08x}",
        0, 0, 1, 0, 0, 0, 0, 0, 0
    );
    debug_assert_eq!(h.len(), 110);
    out.extend_from_slice(h.as_bytes());
    out.extend_from_slice(name.as_bytes());
    out.push(0);
    pad(out);
    out.extend_from_slice(data);
    pad(out);
    Ok(())
}
pub fn append_handoff(
    out: &mut Vec<u8>,
    snapshot: Option<&[u8]>,
    secret: Option<&[u8; 64]>,
) -> Result<()> {
    entry(out, "tpmboot", &[], 0o040700, 1)?;
    if let Some(s) = snapshot {
        entry(out, "tpmboot/enrollment.bin", s, 0o100400, 2)?;
    }
    if let Some(s) = secret {
        entry(out, "tpmboot/secret", s, 0o100400, 3)?;
    }
    entry(out, "TRAILER!!!", &[], 0, 4)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn archive_contains_exact_secret_and_valid_headers() {
        let mut b = Vec::new();
        append_handoff(&mut b, None, Some(&[0x65; 64])).unwrap();
        let mut pos = 0;
        let mut found = false;
        while pos < b.len() {
            assert_eq!(&b[pos..pos + 6], b"070701");
            let number = |start: usize| {
                u32::from_str_radix(
                    core::str::from_utf8(&b[pos + start..pos + start + 8]).unwrap(),
                    16,
                )
                .unwrap() as usize
            };
            let size = number(54);
            let namesize = number(94);
            let name = &b[pos + 110..pos + 110 + namesize - 1];
            pos = (pos + 110 + namesize + 3) & !3;
            if name == b"tpmboot/secret" {
                assert_eq!(&b[pos..pos + size], &[0x65; 64]);
                found = true;
            }
            pos = (pos + size + 3) & !3;
        }
        assert!(found);
        assert_eq!(pos, b.len());
    }
}
