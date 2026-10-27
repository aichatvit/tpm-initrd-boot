#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
if [[ ${1:-} == --help || ${1:-} == -h ]]; then
  echo 'Usage: bash scripts/generate-keys.sh'
  echo 'Create keys/signing.key and keys/public.bin for a NEW installation.'
  echo 'Refuses any existing keys/ directory. No TPM access. Run without sudo.'
  exit 0
fi
[[ $# == 0 ]] || { echo 'Unexpected arguments; use --help.' >&2; exit 2; }
[[ $EUID != 0 ]] || { echo 'Run without sudo.' >&2; exit 1; }
if [[ -e keys || -L keys ]]; then
  echo 'keys/ already exists: nothing changed. Reuse your existing signing keys.' >&2
  exit 1
fi
command -v cargo >/dev/null || { echo 'Install Rust/Cargo via rustup first.' >&2; exit 1; }
umask 077
key_stage=$(mktemp -d "$PWD/.keygen-XXXXXXXX")
trap 'rm -rf -- "$key_stage"' EXIT
cargo run --locked --release -p initrdctl -- keygen \
  "$key_stage/signing.key" "$key_stage/public.bin"
[[ $(wc -c < "$key_stage/signing.key") == 32 ]]
[[ $(wc -c < "$key_stage/public.bin") == 32 ]]
chmod 600 "$key_stage/signing.key" "$key_stage/public.bin"
chmod 700 "$key_stage"
# GNU mv: do not merge with or replace an existing directory, including races.
mv -T -n -- "$key_stage" "$PWD/keys"
[[ ! -d "$key_stage" ]] || { echo 'keys/ appeared during generation; existing files preserved.' >&2; exit 1; }
echo 'Created keys/signing.key (private seed, 32 bytes) and keys/public.bin (32 bytes).'
echo 'Keep signing.key private. These are manifest signing keys, not the 64-byte TPM demo secret.'
