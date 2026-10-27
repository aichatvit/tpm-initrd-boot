#!/usr/bin/env python3
"""Build a Debian/VMware demonstration initramfs. Never use with real secrets.

Does not install files on ESP, change boot entries, or touch the TPM.
Generated initramfs deliberately auto-enrolls a fresh random TEST secret once.
"""
import argparse
import gzip
import json
import lzma
import os
from pathlib import Path
import re
import shutil
import subprocess

INIT_TEMPLATE = r'''#!/bin/sh
PATH=/bin
export PATH
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
mount -t tmpfs -o mode=0700 tmpfs /run
exec </dev/console >/dev/console 2>&1
fail() {
    echo "TPMBOOT LAB FAILED: $*"
    echo 'This is a test RAM shell. reboot -f restarts the VM; poweroff -f stops it.'
    /bin/sh
    poweroff -f
    while :; do sleep 3600; done
}
echo 'TPMBOOT LAB: loading test modules'
while read -r module; do
    [ -n "$module" ] || continue
    insmod "$module" || echo "Module already loaded or unavailable: $module"
done </modules/load-order
esp_device='@@ESP_DEVICE@@'
i=0
while [ ! -b "$esp_device" ] || [ ! -c /dev/tpmrm0 ]; do
    i=$((i+1))
    [ "$i" -lt 30 ] || fail 'ESP device or /dev/tpmrm0 not available'
    sleep 1
done

if [ -f /tpmboot/enrollment.bin ]; then
    echo 'TPMBOOT LAB: first boot, enrollment of a random TEST secret'
    mount -t vfat -o rw "$esp_device" /esp || fail 'mount ESP'
    base=/esp/EFI/TPMBOOT
    [ -f "$base/enroll.request" ] || fail 'enrollment not requested'
    [ ! -e "$base/sealed.bin" ] || fail 'container already exists'
    [ ! -e "$base/lab-secret.sha256" ] || fail 'test already attempted; inspect state manually'
    head -c 64 /dev/urandom >/run/test-secret64 || fail 'random source'
    [ "$(wc -c </run/test-secret64)" -eq 64 ] || fail 'random size'
    if [ '@@DEBUG@@' = 1 ]; then
        echo 'TPMBOOT DEBUG: BEFORE sealing (64 bytes, hex)'
        /bin/busybox hexdump -v -e '16/1 "%02x " "\n"' /run/test-secret64
        echo 'Enrollment continues in 30 seconds...'
        sleep 30
    fi
    sha256sum /run/test-secret64 | cut -d ' ' -f 1 >"$base/lab-secret.sha256"
    initrdctl enroll --authorize-enrollment /tpmboot/enrollment.bin \
      "$base/manifest.bin" "$base/public.bin" /run/test-secret64 "$base/sealed.bin" \
      || fail 'TPM enrollment'
    rm "$base/enroll.request" /run/test-secret64 || fail 'commit enrollment'
    sync
    umount /esp || fail 'unmount ESP'
    echo 'TPMBOOT LAB: enrollment complete; rebooting through the same EFI entry'
    reboot -f
    fail 'reboot returned'
elif [ -f /tpmboot/secret ]; then
    mount -t vfat -o ro "$esp_device" /esp || fail 'mount ESP'
    initrdctl receive /bin/lab-consumer || fail 'consumer comparison'
    umount /esp || fail 'unmount ESP'
    echo
    echo 'TPMBOOT LAB PASS: same 64 bytes recovered after reboot; handoff file removed'
    echo 'Starting Debian in 30 seconds...'
    sleep 30
    mkdir -p /newroot
    root_device=$(/bin/busybox findfs 'UUID=@@ROOT_UUID@@') || fail 'root UUID not found'
    mount -t ext4 -o ro "$root_device" /newroot || fail 'mount Debian root'
    [ -f /newroot/etc/debian_version ] || fail 'not a Debian root'
    [ -d /newroot/lib/modules/$(/bin/busybox uname -r) ] || fail 'kernel modules missing'
    for directory in dev proc sys run; do
        [ -d "/newroot/$directory" ] || fail "missing /$directory"
    done
    echo 'TPMBOOT: switching to Debian'
    mount --move /proc /newroot/proc || fail 'move proc'
    mount --move /sys /newroot/sys || fail 'move sys'
    mount --move /run /newroot/run || fail 'move run'
    mount --move /dev /newroot/dev || fail 'move dev'
    exec /bin/busybox switch_root -c /dev/console /newroot /sbin/init

else
    fail 'neither enrollment snapshot nor secret received from our EFI loader'
fi
'''

CONSUMER = r'''#!/bin/sh
set -eu
PATH=/bin
export PATH
head -c 65 >/run/received64
[ "$(wc -c </run/received64)" -eq 64 ]
if [ '@@DEBUG@@' = 1 ]; then
    echo 'TPMBOOT DEBUG: AFTER unsealing (64 bytes, hex)'
    /bin/busybox hexdump -v -e '16/1 "%02x " "\n"' /run/received64
fi
expected=$(cat /esp/EFI/TPMBOOT/lab-secret.sha256)
actual=$(sha256sum /run/received64 | cut -d ' ' -f 1)
[ "$actual" = "$expected" ]
dd if=/dev/zero of=/run/received64 bs=64 count=1 2>/dev/null
rm /run/received64
echo 'TPMBOOT LAB: consumer verified 64 bytes against the enrollment hash'
'''

class Archive:
    def __init__(self):
        self.data = bytearray()
        self.ino = 0

    def add(self, name, mode, data=b"", rdev=(0, 0)):
        if (name != "TRAILER!!!" and not re.fullmatch(r"[A-Za-z0-9_./-]+", name)) or name.startswith("/") or ".." in name.split("/"):
            raise ValueError("unsafe archive name")
        self.ino += 1
        fields = (self.ino, mode, 0, 0, 1, 0, len(data), 0, 0,
                  rdev[0], rdev[1], len(name) + 1, 0)
        self.data.extend(("070701" + "".join(f"{v:08x}" for v in fields)).encode())
        self.data.extend(name.encode() + b"\0")
        self.data.extend(b"\0" * (-len(self.data) % 4))
        self.data.extend(data)
        self.data.extend(b"\0" * (-len(self.data) % 4))

    def finish(self):
        self.add("TRAILER!!!", 0)
        return bytes(self.data)

def module_bytes(path):
    b = path.read_bytes()
    if path.suffix == ".xz":
        return lzma.decompress(b)
    if path.suffix == ".gz":
        return gzip.decompress(b)
    if path.suffix == ".zst":
        return subprocess.run(["zstd", "-d", "-q", "-c", str(path)],
                              check=True, capture_output=True).stdout
    if path.suffix != ".ko":
        raise ValueError(f"unexpected module extension: {path}")
    return b

def collect_modules(version):
    # Dependencies appear before users in modprobe --show-depends output.
    result, seen = [], set()
    for module in ("tpm_crb", "tpm_tis", "vmw_pvscsi", "mptspi", "ahci", "ata_piix",
                   "nvme", "sd_mod", "ext4", "vfat", "nls_ascii", "nls_cp437", "nls_iso8859_1"):
        p = subprocess.run(["modprobe", "--show-depends", "--set-version", version, module],
                           text=True, capture_output=True)
        if p.returncode:
            print(f"Optional module not present: {module}")
            continue
        for line in p.stdout.splitlines():
            pieces = line.split()
            if len(pieces) >= 2 and pieces[0] == "insmod":
                path = Path(pieces[1]).resolve(strict=True)
                if path not in seen:
                    result.append(path)
                    seen.add(path)
    return result

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--ack-lab-only", action="store_true", required=True)
    p.add_argument("--esp-device", required=True, help="guest ESP partition, e.g. /dev/nvme0n1p1")
    p.add_argument("--kernel-version", default=os.uname().release)
    p.add_argument("--output", default="lab")
    p.add_argument("--root-uuid", default="28fa6bbe-177e-422d-a88e-559ebe08777d")
    p.add_argument("--debug-secret", action="store_true")
    args = p.parse_args()
    if not re.fullmatch(r"/dev/[A-Za-z0-9_-]+", args.esp_device):
        p.error("expected a simple guest device path such as /dev/sda1")
    if not re.fullmatch(r"[A-Za-z0-9_.+-]+", args.kernel_version):
        p.error("invalid kernel version")
    if not re.fullmatch(r"[0-9a-fA-F-]{36}", args.root_uuid):
        p.error("invalid ext4 root UUID")
    project = Path(__file__).resolve().parents[1]
    dist = project / "dist"
    for name in ("initrdctl", "tpmboot.efi", "public.bin"):
        if not (dist / name).is_file():
            p.error("build dist first using scripts/build.sh")
    busybox = Path(shutil.which("busybox") or "/bin/busybox")
    desc = subprocess.check_output(["file", "-b", str(busybox)], text=True)
    if "static" not in desc:
        p.error("install busybox-static; dynamically linked busybox is not supported")
    applets = subprocess.check_output([str(busybox), "--list"], text=True).splitlines()
    for required in ("findfs", "switch_root", "hexdump", "uname"):
        if required not in applets:
            p.error(f"busybox missing applet: {required}")
    kernel = Path("/boot") / ("vmlinuz-" + args.kernel_version)
    if not kernel.is_file():
        p.error(f"kernel image missing: {kernel}")
    modules = collect_modules(args.kernel_version)
    init = (INIT_TEMPLATE.replace("@@ESP_DEVICE@@", args.esp_device)
            .replace("@@ROOT_UUID@@", args.root_uuid)
            .replace("@@DEBUG@@", "1" if args.debug_secret else "0"))
    consumer = CONSUMER.replace("@@DEBUG@@", "1" if args.debug_secret else "0")
    for shell in (init, consumer):
        subprocess.run(["sh", "-n"], input=shell, text=True, check=True)
    a = Archive()
    for directory in ("bin", "dev", "esp", "modules", "proc", "run", "sys"):
        a.add(directory, 0o040755)
    a.add("dev/console", 0o020600, rdev=(5, 1))
    a.add("dev/null", 0o020666, rdev=(1, 3))
    a.add("bin/busybox", 0o100755, busybox.read_bytes())
    for app in ("sh", "mount", "umount", "insmod", "mkdir", "sleep", "head", "cat", "dd",
                "sync", "reboot", "poweroff", "wc", "sha256sum", "cut", "rm"):
        a.add("bin/" + app, 0o120777, b"busybox")
    a.add("bin/initrdctl", 0o100755, (dist / "initrdctl").read_bytes())
    a.add("bin/lab-consumer", 0o100755, consumer.encode())
    a.add("init", 0o100755, init.encode())
    order = []
    for i, path in enumerate(modules):
        name = f"modules/{i:03d}.ko"
        a.add(name, 0o100644, module_bytes(path))
        order.append("/" + name)
    a.add("modules/load-order", 0o100644, ("\n".join(order) + "\n").encode())
    initramfs = gzip.compress(a.finish(), mtime=0)
    if len(initramfs) > 512 * 1024 * 1024:
        p.error("initramfs exceeds EFI loader size limit")
    out = Path(args.output)
    out.mkdir()  # Low-level builder: demo.py supplies a fresh temporary directory.
    shutil.copyfile(kernel, out / "vmlinuz")
    (out / "initramfs.img").write_bytes(initramfs)
    (out / "init").write_text(init)
    (out / "lab-consumer").write_text(consumer)
    (out / "build-info.json").write_text(json.dumps({
        "kernel": args.kernel_version, "esp_device": args.esp_device,
        "modules": [str(x) for x in modules], "mode": "DEMO AUTO-ENROLLMENT", "root_uuid": args.root_uuid, "debug_secret": args.debug_secret
    }, indent=2) + "\n")
    print(f"Created {out}: kernel and test initramfs ({len(initramfs)} bytes, {len(modules)} modules)")
    print("Sign images with the root UUID included in the kernel command line.")
    print("Demo: enroll random TEST secret, reboot, verify, wait 30 seconds, start Debian.")

if __name__ == "__main__":
    main()
