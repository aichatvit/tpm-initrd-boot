#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
if [[ $# != 1 ]]; then
  echo 'Usage: scripts/build.sh /absolute/path/to/public.bin' >&2
  exit 2
fi
public_key=$(realpath "$1")
rustup target add x86_64-unknown-uefi x86_64-unknown-linux-musl
cargo build --locked --release -p initrdctl --target x86_64-unknown-linux-musl
TPMBOOT_PUBLIC_KEY="$public_key" cargo build --locked --release -p efi-loader --target x86_64-unknown-uefi
mkdir -p dist
cp target/x86_64-unknown-uefi/release/tpmboot.efi dist/tpmboot.efi
cp target/x86_64-unknown-linux-musl/release/initrdctl dist/initrdctl
cp "$public_key" dist/public.bin
echo 'Built dist/tpmboot.efi, dist/initrdctl, dist/public.bin'

