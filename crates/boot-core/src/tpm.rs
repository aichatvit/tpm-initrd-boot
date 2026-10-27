//! Minimal TPM 2.0 wire client. SHA-256 bank, RSA storage primary, policy-only sealed data.
//! No TPM ownership changes, persistent handles, NV writes, clear, or PCR allocation.
use crate::{
    Error, Result,
    format::{Container, PCRS, Reader, Snapshot, put_blob},
    hash,
};
use alloc::{vec, vec::Vec};
use zeroize::Zeroizing;

const OWNER: u32 = 0x40000001;
const NULL: u32 = 0x40000007;
const PW: u32 = 0x40000009;
const UNSEAL: u32 = 0x15e;
pub trait Transport {
    fn transact(&mut self, command: &[u8]) -> Result<Vec<u8>>;
}
pub struct Tpm<T> {
    pub transport: T,
}
fn u32b(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_be_bytes());
}
fn u16b(out: &mut Vec<u8>, v: u16) {
    out.extend_from_slice(&v.to_be_bytes());
}
fn selection() -> Vec<u8> {
    vec![0, 0, 0, 1, 0, 0x0b, 3, 0x95, 0x08, 0]
}

impl<T: Transport> Tpm<T> {
    pub fn new(transport: T) -> Self {
        Self { transport }
    }
    fn command(
        &mut self,
        code: u32,
        handles: &[u32],
        params: &[u8],
        auth: Option<u32>,
        out_handles: usize,
    ) -> Result<Zeroizing<Vec<u8>>> {
        let mut b = Zeroizing::new(Vec::new());
        u16b(&mut b, if auth.is_some() { 0x8002 } else { 0x8001 });
        u32b(&mut b, 0);
        u32b(&mut b, code);
        for h in handles {
            u32b(&mut b, *h);
        }
        if let Some(session) = auth {
            u32b(&mut b, 9);
            u32b(&mut b, session);
            u16b(&mut b, 0);
            b.push(0);
            u16b(&mut b, 0);
        }
        b.extend_from_slice(params);
        let len = u32::try_from(b.len()).map_err(|_| Error::Bounds)?;
        b[2..6].copy_from_slice(&len.to_be_bytes());
        let mut response = Zeroizing::new(self.transport.transact(&b)?);
        for _ in 0..8 {
            if response.len() < 10 {
                break;
            }
            let rc = u32::from_be_bytes(response[6..10].try_into().unwrap());
            if !matches!(rc, 0x922 | 0x908 | 0x90a) {
                break;
            }
            response = Zeroizing::new(self.transport.transact(&b)?);
        }
        let mut r = Reader::new(&response);
        let tag = r.u16()?;
        let size = r.u32()? as usize;
        let rc = r.u32()?;
        if size != response.len() || size > 8192 {
            return Err(Error::InvalidFormat);
        }
        if rc != 0 {
            return Err(Error::Tpm(rc));
        }
        let mut result = Zeroizing::new(r.take(out_handles * 4)?.to_vec());
        if auth.is_some() {
            if tag != 0x8002 {
                return Err(Error::InvalidFormat);
            }
            let n = r.u32()? as usize;
            result.extend_from_slice(r.take(n)?);
            // Exactly one authorization response. No response HMAC is expected for these sessions.
            let nonce = r.blob()?;
            if (auth == Some(PW) && !nonce.is_empty()) || nonce.len() > 64 {
                return Err(Error::InvalidFormat);
            }
            r.u8()?;
            if !r.blob()?.is_empty() {
                return Err(Error::InvalidFormat);
            }
            r.finish()?;
        } else {
            if tag != 0x8001 {
                return Err(Error::InvalidFormat);
            }
            result.extend_from_slice(r.take(response.len() - r.pos)?);
        }
        Ok(result)
    }
    pub fn flush(&mut self, handle: u32) -> Result<()> {
        self.command(0x165, &[handle], &[], None, 0)?;
        Ok(())
    }
    pub fn read_pcrs(&mut self, manifest: [u8; 32]) -> Result<Snapshot> {
        let response = self.command(0x17e, &[], &selection(), None, 0)?;
        let mut r = Reader::new(&response);
        r.u32()?; // update counter; one read must return the full selection
        if r.take(10)? != selection() {
            return Err(Error::InvalidFormat);
        }
        if r.u32()? != PCRS.len() as u32 {
            return Err(Error::InvalidFormat);
        }
        let mut values = [[0; 32]; 5];
        for v in &mut values {
            let x = r.blob()?;
            if x.len() != 32 {
                return Err(Error::InvalidFormat);
            }
            v.copy_from_slice(x);
        }
        r.finish()?;
        Ok(Snapshot { manifest, values })
    }
    pub fn extend(&mut self, pcr: u8, data: &[u8]) -> Result<()> {
        let mut p = Vec::new();
        u32b(&mut p, 1);
        u16b(&mut p, 0x0b);
        p.extend_from_slice(&hash(data));
        self.command(0x182, &[pcr as u32], &p, Some(PW), 0)?;
        Ok(())
    }
    fn random(&mut self) -> Result<Vec<u8>> {
        let response = self.command(0x17b, &[], &32u16.to_be_bytes(), None, 0)?;
        let mut r = Reader::new(&response);
        let n = r.blob()?.to_vec();
        r.finish()?;
        if n.len() < 16 {
            return Err(Error::InvalidFormat);
        }
        Ok(n)
    }
    fn start_session(&mut self, trial: bool) -> Result<u32> {
        let mut p = Vec::new();
        put_blob(&mut p, &self.random()?)?;
        put_blob(&mut p, &[])?;
        p.push(if trial { 3 } else { 1 });
        u16b(&mut p, 0x10);
        u16b(&mut p, 0x0b);
        let response = self.command(0x176, &[NULL, NULL], &p, None, 1)?;
        let mut r = Reader::new(&response);
        let handle = r.u32()?;
        r.blob()?;
        r.finish()?;
        Ok(handle)
    }
    fn apply_policy(&mut self, session: u32, snapshot: &Snapshot) -> Result<()> {
        let mut joined = Vec::new();
        for v in &snapshot.values {
            joined.extend_from_slice(v);
        }
        let mut p = Vec::new();
        put_blob(&mut p, &hash(&joined))?;
        p.extend_from_slice(&selection());
        self.command(0x17f, &[session], &p, None, 0)?;
        self.command(0x16c, &[session], &UNSEAL.to_be_bytes(), None, 0)?;
        Ok(())
    }
    pub fn policy_digest(&mut self, snapshot: &Snapshot) -> Result<[u8; 32]> {
        let session = self.start_session(true)?;
        let result = (|| {
            self.apply_policy(session, snapshot)?;
            let response = self.command(0x189, &[session], &[], None, 0)?;
            let mut r = Reader::new(&response);
            let d = r.blob()?.try_into().map_err(|_| Error::InvalidFormat)?;
            r.finish()?;
            Ok(d)
        })();
        let cleanup = self.flush(session);
        match result {
            Ok(v) => {
                cleanup?;
                Ok(v)
            }
            Err(e) => Err(e),
        }
    }
    fn primary(&mut self) -> Result<u32> {
        let mut public = Vec::new();
        u16b(&mut public, 1);
        u16b(&mut public, 0x0b);
        u32b(&mut public, 0x00030072);
        put_blob(&mut public, &[])?; // authPolicy
        u16b(&mut public, 6);
        u16b(&mut public, 128);
        u16b(&mut public, 0x43); // AES-128-CFB
        u16b(&mut public, 0x10);
        u16b(&mut public, 2048);
        u32b(&mut public, 0);
        put_blob(&mut public, &[])?;
        let mut p = Vec::new();
        put_blob(&mut p, &[0, 0, 0, 0])?;
        put_blob(&mut p, &public)?;
        put_blob(&mut p, &[])?;
        u32b(&mut p, 0);
        let response = self.command(0x131, &[OWNER], &p, Some(PW), 1)?;
        let mut r = Reader::new(&response);
        r.u32()
    }
    pub fn seal(&mut self, snapshot: &Snapshot, secret: &[u8; 64]) -> Result<Container> {
        let policy = self.policy_digest(snapshot)?;
        let parent = self.primary()?;
        let result = (|| {
            let mut public = Vec::new();
            u16b(&mut public, 8);
            u16b(&mut public, 0x0b);
            u32b(&mut public, 0x12);
            put_blob(&mut public, &policy)?;
            u16b(&mut public, 0x10);
            put_blob(&mut public, &[])?;
            let mut sensitive = Zeroizing::new(Vec::new());
            put_blob(&mut sensitive, &[])?;
            put_blob(&mut sensitive, secret)?;
            let mut p = Zeroizing::new(Vec::new());
            put_blob(&mut p, &sensitive)?;
            put_blob(&mut p, &public)?;
            put_blob(&mut p, &[])?;
            u32b(&mut p, 0);
            let response = self.command(0x153, &[parent], &p, Some(PW), 0)?;
            let mut r = Reader::new(&response);
            let private = r.blob()?.to_vec();
            let public = r.blob()?.to_vec();
            Ok(Container {
                manifest: snapshot.manifest,
                public,
                private,
            })
        })();
        let cleanup = self.flush(parent);
        match result {
            Ok(v) => {
                cleanup?;
                Ok(v)
            }
            Err(e) => Err(e),
        }
    }
    pub fn unseal(
        &mut self,
        container: &Container,
        snapshot: &Snapshot,
    ) -> Result<Zeroizing<[u8; 64]>> {
        if container.manifest != snapshot.manifest {
            return Err(Error::Mismatch);
        }
        // Refuse password-authorized / migratable objects and policy substitutions.
        let expected = self.policy_digest(snapshot)?;
        let mut r = Reader::new(&container.public);
        if r.u16()? != 8
            || r.u16()? != 0x0b
            || r.u32()? != 0x12
            || r.blob()? != expected
            || r.u16()? != 0x10
        {
            return Err(Error::Mismatch);
        }
        r.blob()?;
        r.finish()?;
        let parent = self.primary()?;
        let result = (|| {
            let mut p = Vec::new();
            put_blob(&mut p, &container.private)?;
            put_blob(&mut p, &container.public)?;
            let response = self.command(0x157, &[parent], &p, Some(PW), 1)?;
            let object = Reader::new(&response).u32()?;
            let result = (|| {
                let session = self.start_session(false)?;
                let result = (|| {
                    self.apply_policy(session, snapshot)?;
                    // continueSession=0 means a successful Unseal destroys this session.
                    let response = self.command(UNSEAL, &[object], &[], Some(session), 0)?;
                    let mut r = Reader::new(&response);
                    let s = r.blob()?;
                    if s.len() != 64 {
                        return Err(Error::InvalidFormat);
                    }
                    let mut secret = Zeroizing::new([0; 64]);
                    secret.copy_from_slice(s);
                    r.finish()?;
                    Ok(secret)
                })();
                if result.is_err() {
                    let _ = self.flush(session);
                }
                result
            })();
            let cleanup = self.flush(object);
            match result {
                Ok(v) => {
                    cleanup?;
                    Ok(v)
                }
                Err(e) => Err(e),
            }
        })();
        let cleanup = self.flush(parent);
        match result {
            Ok(v) => {
                cleanup?;
                Ok(v)
            }
            Err(e) => Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Fake(Vec<u8>);
    impl Transport for Fake {
        fn transact(&mut self, _: &[u8]) -> Result<Vec<u8>> {
            Ok(self.0.clone())
        }
    }
    #[test]
    fn reject_malformed_tpm_header() {
        for b in [vec![], vec![0; 9], vec![0; 10], vec![0; 8193]] {
            assert!(Tpm::new(Fake(b)).read_pcrs([0; 32]).is_err());
        }
    }
    #[test]
    fn pcr_mask_matches_indices() {
        let s = selection();
        let mut indices = Vec::new();
        for i in 0..24 {
            if s[7 + i / 8] & (1 << (i % 8)) != 0 {
                indices.push(i as u8);
            }
        }
        assert_eq!(indices, PCRS);
    }
}
