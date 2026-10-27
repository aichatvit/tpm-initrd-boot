#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
if [[ ${1:-} == --help || ${1:-} == -h ]]; then
  cat <<'HELP'
Usage: bash scripts/build-demo.sh [--no-debug-secret] [prepare options]
Build EFI and Linux utility, then prepare signed demo/ using existing keys/.
Hex output is enabled by default for this demonstration wrapper.
Options passed to prepare: --esp-device DEVICE --root-uuid UUID --kernel-version VERSION
Run as your normal user. sudo is used only for initramfs preparation.
HELP
  exit 0
fi
if [[ $EUID == 0 ]]; then
  echo 'Run build-demo.sh without sudo; it requests sudo for initramfs preparation.' >&2
  exit 1
fi
for name in keys/signing.key keys/public.bin; do
  [[ -f "$name" ]] || { echo "Missing $name. Copy existing keys/ or run scripts/generate-keys.sh for a NEW installation." >&2; exit 1; }
done
secret_args=(--debug-secret)
prepare_args=()
for arg in "$@"; do
  if [[ "$arg" == --no-debug-secret ]]; then
    secret_args=()
  else
    prepare_args+=("$arg")
  fi
done
bash scripts/build.sh "$PWD/keys/public.bin"
sudo python3 scripts/demo.py prepare "${secret_args[@]}" "${prepare_args[@]}"
echo 'Build complete: demo/. Install with: bash scripts/install-demo.sh --reenroll'
