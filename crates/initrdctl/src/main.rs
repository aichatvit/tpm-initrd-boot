use boot_core::{
    format::{Container, Manifest, Snapshot},
    hash,
    tpm::{Tpm, Transport},
};
use ed25519_dalek::{Signer, SigningKey};
use std::{
    env,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::{fs::OpenOptionsExt, net::UnixStream},
    path::Path,
};
use zeroize::Zeroizing;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
fn core<T>(v: boot_core::Result<T>) -> Result<T> {
    v.map_err(|e| format!("protocol: {e:?}").into())
}

enum Channel {
    Device(File),
    Simulator(UnixStream),
    Process(std::process::Child),
}
impl Drop for Channel {
    fn drop(&mut self) {
        if let Self::Process(p) = self {
            let _ = p.kill();
            let _ = p.wait();
        }
    }
}
fn stream_reply(s: &mut impl Read) -> boot_core::Result<Vec<u8>> {
    use boot_core::Error;
    let mut h = [0; 10];
    s.read_exact(&mut h).map_err(|_| Error::Transport)?;
    let n = u32::from_be_bytes(h[2..6].try_into().unwrap()) as usize;
    if !(10..=8192).contains(&n) {
        return Err(Error::InvalidFormat);
    }
    let mut b = vec![0; n];
    b[..10].copy_from_slice(&h);
    s.read_exact(&mut b[10..]).map_err(|_| Error::Transport)?;
    Ok(b)
}
impl Transport for Channel {
    fn transact(&mut self, command: &[u8]) -> boot_core::Result<Vec<u8>> {
        use boot_core::Error;
        match self {
            Self::Device(f) => {
                // TPM character devices require a single write and a single sufficiently large read.
                if f.write(command).map_err(|_| Error::Transport)? != command.len() {
                    return Err(Error::Transport);
                }
                let mut b = vec![0; 8192];
                let n = f.read(&mut b).map_err(|_| Error::Transport)?;
                b.truncate(n);
                Ok(b)
            }
            Self::Simulator(s) => {
                s.write_all(command).map_err(|_| Error::Transport)?;
                stream_reply(s)
            }
            Self::Process(p) => {
                let input = p.stdin.as_mut().ok_or(Error::Transport)?;
                input.write_all(command).map_err(|_| Error::Transport)?;
                input.flush().map_err(|_| Error::Transport)?;
                stream_reply(p.stdout.as_mut().ok_or(Error::Transport)?)
            }
        }
    }
}
fn device(path: &str) -> Result<Channel> {
    Ok(Channel::Device(
        OpenOptions::new().read(true).write(true).open(path)?,
    ))
}
fn limited(path: &str, max: usize) -> Result<Vec<u8>> {
    let mut b = Vec::new();
    File::open(path)?
        .take((max + 1) as u64)
        .read_to_end(&mut b)?;
    if b.len() > max {
        return Err("file exceeds size limit".into());
    }
    Ok(b)
}
fn fixed<const N: usize>(path: &str) -> Result<Zeroizing<[u8; N]>> {
    let mut b = Zeroizing::new(Vec::new());
    File::open(path)?.take((N + 1) as u64).read_to_end(&mut b)?;
    if b.len() != N {
        return Err(format!("expected exactly {N} bytes").into());
    }
    let mut a = Zeroizing::new([0; N]);
    a.copy_from_slice(&b);
    Ok(a)
}
fn write_new(path: &str, b: &[u8]) -> Result<()> {
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(b)?;
    f.sync_all()?;
    let parent = Path::new(path)
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    File::open(parent)?.sync_all()?;
    Ok(())
}
fn enroll(a: &[String]) -> Result<()> {
    if a.len() != 6 || a[0] != "--authorize-enrollment" {
        return Err("enroll requires explicit --authorize-enrollment; see --help".into());
    }
    let snapshot = core(Snapshot::decode(&limited(&a[1], 1024)?))?;
    let manifest = limited(&a[2], 4096)?;
    let public = fixed::<32>(&a[3])?;
    core(Manifest::verify(&manifest, &public))?;
    if hash(&manifest) != snapshot.manifest {
        return Err("snapshot belongs to another manifest".into());
    }
    if Path::new(&a[5]).exists() {
        return Err("container exists; refusing automatic replacement".into());
    }
    let secret = fixed::<64>(&a[4])?;
    let mut tpm = Tpm::new(device("/dev/tpmrm0")?);
    let container = core(tpm.seal(&snapshot, &secret))?;
    write_new(&a[5], &core(container.encode())?)?;
    eprintln!("Enrollment complete. Reboot through the same EFI entry to verify Unseal.");
    Ok(())
}
fn deliver(a: &[String]) -> Result<()> {
    if a.len() != 1 {
        return Err("receive requires executable path (no arguments)".into());
    }
    if !Path::new(&a[0]).is_absolute() {
        return Err("consumer path must be absolute".into());
    }
    // The consumer gets bytes on stdin; no secret appears in argv/environment/output logs.
    let secret = fixed::<64>("/tpmboot/secret")?;
    let mut child = std::process::Command::new(&a[0])
        .stdin(std::process::Stdio::piped())
        .spawn()?;
    child
        .stdin
        .take()
        .ok_or("consumer stdin unavailable")?
        .write_all(&secret[..])?;
    let status = child.wait()?;
    if !status.success() {
        return Err("consumer failed; secret file retained for explicit handling".into());
    }
    let mut f = OpenOptions::new().write(true).open("/tpmboot/secret")?;
    f.write_all(&[0; 64])?;
    drop(f);
    fs::remove_file("/tpmboot/secret")?;
    Ok(())
}
fn simulator_test(channel: Channel, bridge: Option<&str>) -> Result<()> {
    let mut tpm = Tpm::new(channel);
    // Startup is exclusively a simulator-test operation; firmware owns startup on real hardware.
    let startup = [0x80, 0x01, 0, 0, 0, 12, 0, 0, 1, 0x44, 0, 0];
    let _ = tpm.transport.transact(&startup);
    core(tpm.extend(4, b"test firmware measures loader"))?;
    core(tpm.extend(11, b"test loader measures manifest"))?;
    let before = core(tpm.read_pcrs([42; 32]))?;
    let secret = [0x6a; 64];
    let c = core(tpm.seal(&before, &secret))?;
    let decoded = core(Container::decode(&core(c.encode())?))?;
    let actual = core(tpm.unseal(&decoded, &before))?;
    if *actual != secret {
        return Err("unsealed value differs".into());
    }
    core(tpm.extend(11, b"integration-phase-closed"))?;
    // Use the old snapshot: PolicyPCR must fail in a real policy session.
    if !matches!(tpm.unseal(&decoded, &before), Err(boot_core::Error::Tpm(_))) {
        return Err("PCR change unexpectedly allowed Unseal".into());
    }
    // Create using earlier PCRs while current PCRs differ: matches enrollment in initramfs.
    let c2 = core(tpm.seal(&before, &secret))?;
    if !matches!(tpm.unseal(&c2, &before), Err(boot_core::Error::Tpm(_))) {
        return Err("old-state object opened in new state".into());
    }
    let now = core(tpm.read_pcrs([42; 32]))?;
    let c3 = core(tpm.seal(&now, &secret))?;
    if *core(tpm.unseal(&c3, &now))? != secret {
        return Err("second roundtrip differs".into());
    }
    // The pipe bridge can emulate a cold restart while preserving TPM permanent state.
    if matches!(&tpm.transport, Channel::Process(_)) {
        core(
            tpm.transport
                .transact(&[0x80, 1, 0, 0, 0, 10, 0xff, 0xff, 0xff, 0xff]),
        )?;
        core(tpm.transport.transact(&startup))?;
        core(tpm.extend(4, b"test firmware measures loader"))?;
        core(tpm.extend(11, b"test loader measures manifest"))?;
        let next = core(tpm.read_pcrs([42; 32]))?;
        if next != before {
            return Err("PCR state did not repeat after cold restart".into());
        }
        if *core(tpm.unseal(&c2, &next))? != secret {
            return Err("cold-restart unseal differs".into());
        }
        core(
            tpm.transport
                .transact(&[0x80, 1, 0, 0, 0, 10, 0xff, 0xff, 0xff, 0xff]),
        )?;
        core(tpm.transport.transact(&startup))?;
        core(tpm.extend(4, b"tampered EFI loader"))?;
        core(tpm.extend(11, b"test loader measures manifest"))?;
        if !matches!(tpm.unseal(&c2, &before), Err(boot_core::Error::Tpm(_))) {
            return Err("tampered-loader PCR was not denied by TPM".into());
        }
        eprintln!(
            "PASS: cold restart preserves object; repeated chain opens; altered loader denied"
        );
        if let Some(bridge) = bridge {
            let child = std::process::Command::new(bridge)
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .spawn()?;
            let mut other = Tpm::new(Channel::Process(child));
            core(other.transport.transact(&startup))?;
            if !matches!(other.unseal(&c2, &before), Err(boot_core::Error::Tpm(_))) {
                return Err("copied object was not denied by another TPM".into());
            }
            eprintln!("PASS: copied sealed object rejected by a fresh independent TPM");
        }
    }
    eprintln!(
        "PASS: sealed roundtrip, PCR mismatch denied, enrollment for earlier PCRs, changed-state roundtrip"
    );
    Ok(())
}
fn run() -> Result<()> {
    let a: Vec<String> = env::args().skip(1).collect();
    match a.first().map(String::as_str) {
        Some("keygen") if a.len() == 3 => {
            let mut seed = Zeroizing::new([0; 32]);
            File::open("/dev/urandom")?.read_exact(&mut *seed)?;
            let k = SigningKey::from_bytes(&seed);
            write_new(&a[1], &seed[..])?;
            write_new(&a[2], &k.verifying_key().to_bytes())?;
        }
        Some("sign") if a.len() == 6 => {
            let seed = fixed::<32>(&a[1])?;
            let key = SigningKey::from_bytes(&seed);
            let m = Manifest {
                kernel: hash(&limited(&a[2], 128 * 1024 * 1024)?),
                initrd: hash(&limited(&a[3], 512 * 1024 * 1024)?),
                cmdline: a[4].clone(),
            };
            let mut b = core(m.unsigned())?;
            let sig = key.sign(&b);
            b.extend_from_slice(&sig.to_bytes());
            write_new(&a[5], &b)?;
        }
        Some("verify") if a.len() == 5 => {
            let m = core(Manifest::verify(
                &limited(&a[1], 4096)?,
                &*fixed::<32>(&a[2])?,
            ))?;
            core(m.verify_images(
                &limited(&a[3], 128 * 1024 * 1024)?,
                &limited(&a[4], 512 * 1024 * 1024)?,
            ))?;
            eprintln!("Manifest signature and image hashes verified.");
        }
        Some("pehash") if a.len() == 2 => {
            let digest = core(boot_core::pe::unsigned_efi_digest(&limited(
                &a[1],
                16 * 1024 * 1024,
            )?))?;
            for b in digest {
                print!("{b:02x}");
            }
            println!();
        }
        Some("enroll") => enroll(&a[1..])?,
        Some("receive") => deliver(&a[1..])?,
        Some("test-swtpm") if a.len() == 2 => {
            let s = UnixStream::connect(&a[1])?;
            s.set_read_timeout(Some(std::time::Duration::from_secs(20)))?;
            simulator_test(Channel::Simulator(s), None)?;
        }
        Some("test-process") if a.len() == 2 => {
            let p = std::process::Command::new(&a[1])
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .spawn()?;
            simulator_test(Channel::Process(p), Some(&a[1]))?;
        }
        Some("--help") | None => eprintln!(
            "initrdctl keygen PRIVATE_SEED PUBLIC_KEY\ninitrdctl sign PRIVATE_SEED KERNEL INITRAMFS 'CMDLINE' MANIFEST\ninitrdctl verify MANIFEST PUBLIC_KEY KERNEL INITRAMFS\ninitrdctl enroll --authorize-enrollment SNAPSHOT MANIFEST PUBLIC_KEY SECRET64 CONTAINER\ninitrdctl receive /absolute/path/to/consumer\ninitrdctl test-swtpm UNIX_SOCKET\n\nAll output files are create-only. Enroll uses /dev/tpmrm0. Secret is exactly 64 binary bytes.\nEnrollment is an explicit trusted-administrator operation, never an automatic missing-file fallback."
        ),
        _ => return Err("invalid command; use --help".into()),
    }
    Ok(())
}
fn main() {
    if let Err(e) = run() {
        eprintln!("initrdctl: {e}");
        std::process::exit(1);
    }
}
