use crate::{Error, Result, hash};
use alloc::{string::String, vec::Vec};
use ed25519_dalek::{Signature, VerifyingKey};

pub const PCRS: [u8; 5] = [0, 2, 4, 7, 11];
pub const MAX_MANIFEST: usize = 4096;
pub const MAX_CONTAINER: usize = 4096;
pub const MEASUREMENT_DOMAIN: &[u8] = b"TPMBOOT-MANIFEST-v1\0";
pub const CLOSED_PHASE: &[u8] = b"TPMBOOT-UNSEAL-CLOSED-v1";

pub struct Reader<'a> {
    pub bytes: &'a [u8],
    pub pos: usize,
}
impl<'a> Reader<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }
    pub fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self.pos.checked_add(n).ok_or(Error::Bounds)?;
        let v = self.bytes.get(self.pos..end).ok_or(Error::Bounds)?;
        self.pos = end;
        Ok(v)
    }
    pub fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    pub fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().unwrap()))
    }
    pub fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }
    pub fn blob(&mut self) -> Result<&'a [u8]> {
        let n = self.u16()? as usize;
        self.take(n)
    }
    pub fn finish(&self) -> Result<()> {
        if self.pos == self.bytes.len() {
            Ok(())
        } else {
            Err(Error::InvalidFormat)
        }
    }
}
pub fn put_blob(v: &mut Vec<u8>, b: &[u8]) -> Result<()> {
    let n = u16::try_from(b.len()).map_err(|_| Error::Bounds)?;
    v.extend_from_slice(&n.to_be_bytes());
    v.extend_from_slice(b);
    Ok(())
}

pub struct Manifest {
    pub kernel: [u8; 32],
    pub initrd: [u8; 32],
    pub cmdline: String,
}
impl Manifest {
    pub fn unsigned(&self) -> Result<Vec<u8>> {
        if self.cmdline.len() > 2048 || self.cmdline.chars().any(|c| c == '\0' || c.is_control()) {
            return Err(Error::InvalidFormat);
        }
        let mut b = Vec::from(&b"TPMBMF01"[..]);
        b.extend_from_slice(&self.kernel);
        b.extend_from_slice(&self.initrd);
        put_blob(&mut b, self.cmdline.as_bytes())?;
        Ok(b)
    }
    pub fn verify(signed: &[u8], key: &[u8; 32]) -> Result<Self> {
        if signed.len() > MAX_MANIFEST || signed.len() < 64 {
            return Err(Error::Bounds);
        }
        let (body, sig) = signed.split_at(signed.len() - 64);
        let key = VerifyingKey::from_bytes(key).map_err(|_| Error::Signature)?;
        let sig = Signature::from_slice(sig).map_err(|_| Error::Signature)?;
        key.verify_strict(body, &sig)
            .map_err(|_| Error::Signature)?;
        let mut r = Reader::new(body);
        if r.take(8)? != b"TPMBMF01" {
            return Err(Error::InvalidFormat);
        }
        let m = Self {
            kernel: r.take(32)?.try_into().unwrap(),
            initrd: r.take(32)?.try_into().unwrap(),
            cmdline: core::str::from_utf8(r.blob()?)
                .map_err(|_| Error::InvalidFormat)?
                .into(),
        };
        r.finish()?;
        m.unsigned()?;
        Ok(m)
    }
    pub fn verify_images(&self, kernel: &[u8], initrd: &[u8]) -> Result<()> {
        if hash(kernel) != self.kernel || hash(initrd) != self.initrd {
            Err(Error::Mismatch)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Snapshot {
    pub manifest: [u8; 32],
    pub values: [[u8; 32]; 5],
}
impl Snapshot {
    pub fn encode(&self) -> Vec<u8> {
        let mut b = Vec::from(&b"TPMBSN01"[..]);
        b.extend_from_slice(&self.manifest);
        b.push(5);
        for (i, pcr) in PCRS.iter().enumerate() {
            b.push(*pcr);
            b.extend_from_slice(&self.values[i]);
        }
        b
    }
    pub fn decode(b: &[u8]) -> Result<Self> {
        let mut r = Reader::new(b);
        if r.take(8)? != b"TPMBSN01" {
            return Err(Error::InvalidFormat);
        }
        let manifest = r.take(32)?.try_into().unwrap();
        if r.u8()? != 5 {
            return Err(Error::InvalidFormat);
        }
        let mut values = [[0; 32]; 5];
        for (i, pcr) in PCRS.iter().enumerate() {
            if r.u8()? != *pcr {
                return Err(Error::InvalidFormat);
            }
            values[i].copy_from_slice(r.take(32)?);
        }
        r.finish()?;
        Ok(Self { manifest, values })
    }
}

pub struct Container {
    pub manifest: [u8; 32],
    pub public: Vec<u8>,
    pub private: Vec<u8>,
}
impl Container {
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut b = Vec::from(&b"TPMBCT01"[..]);
        b.extend_from_slice(&self.manifest);
        put_blob(&mut b, &self.public)?;
        put_blob(&mut b, &self.private)?;
        if b.len() > MAX_CONTAINER {
            return Err(Error::Bounds);
        }
        Ok(b)
    }
    pub fn decode(b: &[u8]) -> Result<Self> {
        if b.len() > MAX_CONTAINER {
            return Err(Error::Bounds);
        }
        let mut r = Reader::new(b);
        if r.take(8)? != b"TPMBCT01" {
            return Err(Error::InvalidFormat);
        }
        let c = Self {
            manifest: r.take(32)?.try_into().unwrap(),
            public: r.blob()?.into(),
            private: r.blob()?.into(),
        };
        r.finish()?;
        if c.public.is_empty() || c.private.is_empty() {
            return Err(Error::InvalidFormat);
        }
        Ok(c)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    #[test]
    fn signed_manifest_rejects_changes() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let m = Manifest {
            kernel: hash(b"kernel"),
            initrd: hash(b"initrd"),
            cmdline: "quiet".into(),
        };
        let mut b = m.unsigned().unwrap();
        let sig = key.sign(&b);
        b.extend_from_slice(&sig.to_bytes());
        let checked = Manifest::verify(&b, &key.verifying_key().to_bytes()).unwrap();
        checked.verify_images(b"kernel", b"initrd").unwrap();
        assert!(checked.verify_images(b"changed", b"initrd").is_err());
        b[20] ^= 1;
        assert!(Manifest::verify(&b, &key.verifying_key().to_bytes()).is_err());
    }
    #[test]
    fn snapshot_strict_roundtrip() {
        let s = Snapshot {
            manifest: [3; 32],
            values: [[4; 32]; 5],
        };
        let b = s.encode();
        assert_eq!(Snapshot::decode(&b).unwrap(), s);
        for n in 0..b.len() {
            assert!(Snapshot::decode(&b[..n]).is_err());
        }
        let mut b = b;
        b.push(0);
        assert!(Snapshot::decode(&b).is_err());
    }
    #[test]
    fn container_rejects_truncation_and_trailing_data() {
        let b = Container {
            manifest: [0; 32],
            public: alloc::vec![1;20],
            private: alloc::vec![2;32],
        }
        .encode()
        .unwrap();
        for n in 0..b.len() {
            assert!(Container::decode(&b[..n]).is_err());
        }
        Container::decode(&b).unwrap();
        let mut b = b;
        b.push(0);
        assert!(Container::decode(&b).is_err());
    }
}
