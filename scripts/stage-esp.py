#!/usr/bin/env python3
"""Stage a new EFI/TPMBOOT directory; does not change firmware boot variables.
Never overwrites an installed project. Run from a trusted Linux installer.
"""
import os
from pathlib import Path
import shutil
import subprocess
import sys

if len(sys.argv) != 6:
    sys.exit("Usage: stage-esp.py ESP KERNEL INITRAMFS MANIFEST DIST_DIRECTORY")
esp, kernel, initrd, manifest, dist = map(lambda x: Path(x).resolve(), sys.argv[1:])
if not (esp.is_dir() and os.path.ismount(esp)):
    sys.exit("ESP must be an existing mount point; refusing to write to an unmounted path")
subprocess.run([str(dist / "initrdctl"), "verify", str(manifest),
                str(dist / "public.bin"), str(kernel), str(initrd)], check=True)
parent = esp / "EFI"
parent.mkdir(exist_ok=True)
target = parent / "TPMBOOT"
target.mkdir()  # Atomic create, fails when an installation already exists.
files = {"tpmboot.efi": dist / "tpmboot.efi", "vmlinuz.efi": kernel,
         "initramfs.img": initrd, "manifest.bin": manifest,
         "public.bin": dist / "public.bin"}
for name, source in files.items():
    with source.open("rb") as src, (target / name).open("xb") as dst:
        shutil.copyfileobj(src, dst)
        dst.flush()
        os.fsync(dst.fileno())
with (target / "enroll.request").open("xb") as f:
    f.write(b"TPMBOOT-ENROLL-v1\n")
    f.flush()
    os.fsync(f.fileno())
os.sync()
print(f"Staged {target}. Boot entry was not changed.")
print(r"Create a dedicated firmware entry for \EFI\TPMBOOT\tpmboot.efi using the correct disk and ESP partition.")
print("Use that same entry for registration and all later boots.")

