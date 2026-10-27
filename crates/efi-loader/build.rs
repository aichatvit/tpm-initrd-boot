use std::{env, fs, path::PathBuf};
fn main() {
    println!("cargo:rerun-if-env-changed=TPMBOOT_PUBLIC_KEY");
    let path=env::var("TPMBOOT_PUBLIC_KEY").expect("set TPMBOOT_PUBLIC_KEY to your raw 32-byte Ed25519 public-key file; no default trust key is allowed");
    println!("cargo:rerun-if-changed={path}");
    let b = fs::read(&path).expect("read public key");
    assert_eq!(b.len(), 32, "public key must be exactly 32 binary bytes");
    fs::write(
        PathBuf::from(env::var_os("OUT_DIR").unwrap()).join("public-key.bin"),
        b,
    )
    .unwrap();
}
