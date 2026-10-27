#!/usr/bin/env python3
"""Repeatable demo preparation/install. Does not clear TPM or edit boot entries."""
import argparse
import fcntl
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

PROJECT = Path(__file__).resolve().parents[1]
FILES = ('tpmboot.efi', 'vmlinuz.efi', 'initramfs.img', 'manifest.bin', 'public.bin')
MARKER = b'TPMBOOT-ENROLL-v1\n'
BACKUP_ROOT = Path('/var/backups/tpmboot-demo')


def run(*args):
    subprocess.run([str(a) for a in args], check=True)


def verify(directory):
    run(PROJECT / 'dist/initrdctl', 'verify', directory / 'manifest.bin',
        directory / 'public.bin', directory / 'vmlinuz.efi', directory / 'initramfs.img')


def same_bundle(a, b):
    return all((a / n).is_file() and (b / n).is_file() and
               (a / n).read_bytes() == (b / n).read_bytes() for n in FILES)


def publish(stage, destination, retired):
    """Restore old directory if the second rename fails. Not power-loss atomic."""
    moved = False
    if destination.exists():
        destination.rename(retired)
        moved = True
    try:
        stage.rename(destination)
    except BaseException:
        if moved:
            retired.rename(destination)
        raise
    os.sync()


def prepare(args):
    dist = PROJECT / 'dist'
    for name in ('tpmboot.efi', 'initrdctl', 'public.bin'):
        if not (dist / name).is_file():
            raise RuntimeError('Run bash scripts/build.sh keys/public.bin first')
    key = Path(args.key).resolve()
    if not key.is_file():
        raise RuntimeError('Existing signing key not found; do not regenerate keys for this VM')
    root_uuid = args.root_uuid
    # A persistent directory is replaced only after the entire new bundle verifies.
    with tempfile.TemporaryDirectory(prefix='.demo-build-', dir=PROJECT) as temp:
        work = Path(temp)
        lab = work / 'lab'
        command = ['python3', PROJECT / 'scripts/vmware-lab.py', '--ack-lab-only',
                   '--esp-device', args.esp_device, '--root-uuid', root_uuid,
                   '--kernel-version', args.kernel_version or os.uname().release,
                   '--output', lab]
        if args.debug_secret:
            command.append('--debug-secret')
        run(*command)
        stage = work / 'bundle'
        stage.mkdir()
        for source, name in ((lab / 'vmlinuz', 'vmlinuz.efi'),
                             (lab / 'initramfs.img', 'initramfs.img'),
                             (dist / 'tpmboot.efi', 'tpmboot.efi'),
                             (dist / 'public.bin', 'public.bin')):
            shutil.copy2(source, stage / name)
        cmdline = f'root=UUID={root_uuid} ro console=tty0 loglevel=4'
        run(dist / 'initrdctl', 'sign', key, stage / 'vmlinuz.efi',
            stage / 'initramfs.img', cmdline, stage / 'manifest.bin')
        verify(stage)
        for name in ('init', 'lab-consumer', 'build-info.json'):
            shutil.copy2(lab / name, stage / name)
        backups = PROJECT / 'demo-backups'
        backups.mkdir(exist_ok=True)
        slot = Path(tempfile.mkdtemp(prefix='build-', dir=backups))
        publish(stage, PROJECT / 'demo', slot / 'demo')
    print('Prepared: demo/ (constant name). No ESP or TPM changes.')


def install(args):
    if os.geteuid() != 0:
        raise RuntimeError('Run install with sudo')
    esp = Path(args.esp).resolve()
    if not esp.is_mount():
        raise RuntimeError('ESP must be a mounted filesystem')
    bundle = PROJECT / 'demo'
    verify(bundle)
    for name in FILES:
        if not (bundle / name).is_file():
            raise RuntimeError(f'Missing {name}')
    parent = esp / 'EFI'
    parent.mkdir(exist_ok=True)
    target = parent / 'TPMBOOT'
    if target.is_symlink():
        raise RuntimeError('Refusing symlink target')
    if target.exists() and same_bundle(bundle, target) and not args.reenroll:
        print('Identical bundle already installed; sealed secret and enrollment state preserved.')
        return
    if target.exists() and not args.reenroll:
        raise RuntimeError('Bundle changed. Use install --reenroll for a NEW RANDOM TEST secret; old bundle is backed up.')
    if not target.exists() and not args.reenroll:
        raise RuntimeError('First demo enrollment requires install --reenroll')
    backups = BACKUP_ROOT
    backups.mkdir(mode=0o700, parents=True, exist_ok=True)
    slot = Path(tempfile.mkdtemp(prefix='install-', dir=backups))
    if target.exists():
        shutil.copytree(target, slot / 'TPMBOOT')
        for old in target.iterdir():
            if old.is_file() and (slot / 'TPMBOOT' / old.name).read_bytes() != old.read_bytes():
                raise RuntimeError('Backup verification failed')
    os.sync()
    work = Path(tempfile.mkdtemp(prefix='.tpmboot-stage-', dir=parent))
    try:
        stage = work / 'new'
        stage.mkdir()
        for name in FILES:
            shutil.copy2(bundle / name, stage / name)
        (stage / 'enroll.request').write_bytes(MARKER)
        verify(stage)
        os.sync()
        publish(stage, target, work / 'previous')
    except BaseException:
        print(f'Install interrupted. Backup: {slot}; staging/recovery directory: {work}')
        raise
    else:
        shutil.rmtree(work)
        os.sync()
    print(f'Installed. Backup: {slot}/TPMBOOT')
    print('Next boot enrolls a NEW RANDOM TEST secret and reboots automatically.')
    print('Then: hex output if enabled -> PASS -> 30 seconds -> Debian.')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest='action', required=True)
    b = sub.add_parser('prepare', help='rebuild demo/ using existing dist/ and signing key')
    b.add_argument('--key', default=str(PROJECT / 'keys/signing.key'))
    b.add_argument('--esp-device', default='/dev/sda1')
    b.add_argument('--root-uuid', default='28fa6bbe-177e-422d-a88e-559ebe08777d')
    b.add_argument('--kernel-version')
    b.add_argument('--debug-secret', action='store_true', help='print random TEST secret in hex before/after TPM sealing')
    i = sub.add_parser('install', help='install prepared demo/ to mounted ESP')
    i.add_argument('--esp', default='/boot/efi')
    i.add_argument('--reenroll', action='store_true', help='explicitly enroll a NEW RANDOM TEST secret; back up existing bundle')
    args = p.parse_args()
    # Prevent concurrent prepare/install commands in this project checkout.
    with (PROJECT / '.demo.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        (prepare if args.action == 'prepare' else install)(args)


if __name__ == '__main__':
    try:
        main()
    except (OSError, RuntimeError, subprocess.CalledProcessError) as e:
        raise SystemExit(f'demo: {e}')
