#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
cargo test --locked -p boot-core -p initrdctl
python3 tests/test_cli.py
python3 tests/test_demo.py
if [[ ${TPMBOOT_SKIP_SIMULATOR:-0} != 1 ]]; then
  cargo run --locked -q -p initrdctl -- test-process "$PWD/tests/libtpms_bridge.py"
fi

