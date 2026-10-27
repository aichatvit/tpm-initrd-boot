#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
if [[ ${1:-} == --help || ${1:-} == -h ]]; then
  cat <<'HELP'
Usage: bash scripts/install-demo.sh [--reenroll] [--esp /boot/efi]
Install verified demo/ with an automatic backup of the installed bundle.
--reenroll explicitly enables a NEW RANDOM TEST SECRET on the next boot.
Without it: identical bundle is preserved; changed bundle is refused.
Does not clear TPM, change BootOrder or reboot the machine.
HELP
  exit 0
fi
if [[ $EUID == 0 ]]; then
  python3 scripts/demo.py install "$@"
else
  sudo python3 scripts/demo.py install "$@"
fi
