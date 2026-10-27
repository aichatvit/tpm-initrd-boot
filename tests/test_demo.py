#!/usr/bin/env python3
import importlib.util
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'scripts' / (name + '.py'))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

demo = load('demo')
lab = load('vmware-lab')

class DemoTests(unittest.TestCase):
    def test_generated_shell(self):
        for debug in ('0', '1'):
            init = lab.INIT_TEMPLATE.replace('@@ESP_DEVICE@@', '/dev/sda1').replace('@@ROOT_UUID@@', '28fa6bbe-177e-422d-a88e-559ebe08777d').replace('@@DEBUG@@', debug)
            consumer = lab.CONSUMER.replace('@@DEBUG@@', debug)
            for s in (init, consumer):
                self.assertNotIn('@@', s)
                subprocess.run(['sh', '-n'], input=s, text=True, check=True)

    def test_publish_repeated_and_rollback(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            dest = root / 'demo'
            dest.mkdir()
            (dest / 'version').write_text('old')
            stage = root / 'stage'
            stage.mkdir()
            (stage / 'version').write_text('new')
            retired = root / 'previous'
            original = Path.rename
            def fail_stage(path, target):
                if path == stage:
                    raise OSError('injected rename failure')
                return original(path, target)
            with patch.object(Path, 'rename', fail_stage), patch.object(demo.os, 'sync'):
                with self.assertRaises(OSError):
                    demo.publish(stage, dest, retired)
            self.assertEqual((dest / 'version').read_text(), 'old')
            with patch.object(demo.os, 'sync'):
                demo.publish(stage, dest, retired)
            self.assertEqual((dest / 'version').read_text(), 'new')
            self.assertEqual((retired / 'version').read_text(), 'old')

    def test_install_requires_reenrollment_and_preserves_unchanged_secret(self):
        with tempfile.TemporaryDirectory() as td:
            project = Path(td)
            bundle = project / 'demo'
            bundle.mkdir()
            for name in demo.FILES:
                (bundle / name).write_bytes(name.encode())
            esp = project / 'esp'
            esp.mkdir()
            args = SimpleNamespace(esp=str(esp), reenroll=False)
            with patch.object(demo, 'PROJECT', project), patch.object(demo, 'BACKUP_ROOT', project / 'backups'), patch.object(demo, 'verify'), patch.object(demo.os, 'geteuid', return_value=0), patch.object(demo.os, 'sync'), patch.object(Path, 'is_mount', return_value=True):
                with self.assertRaises(RuntimeError):
                    demo.install(args)
                args.reenroll = True
                demo.install(args)
                target = esp / 'EFI/TPMBOOT'
                self.assertEqual((target / 'enroll.request').read_bytes(), demo.MARKER)
                (target / 'enroll.request').unlink()
                (target / 'sealed.bin').write_bytes(b'old-secret-container')
                args.reenroll = False
                demo.install(args)
                self.assertEqual((target / 'sealed.bin').read_bytes(), b'old-secret-container')
                (bundle / 'initramfs.img').write_bytes(b'new-image')
                with self.assertRaises(RuntimeError):
                    demo.install(args)
                self.assertTrue((target / 'sealed.bin').exists())
                args.reenroll = True
                demo.install(args)
                self.assertFalse((target / 'sealed.bin').exists())
                copies = list((project / 'backups').glob('*/TPMBOOT/sealed.bin'))
                self.assertEqual(len(copies), 1)
                self.assertEqual(copies[0].read_bytes(), b'old-secret-container')

    def test_bundle_comparison_ignores_sealed_state_but_detects_images(self):
        with tempfile.TemporaryDirectory() as td:
            a, b = Path(td) / 'a', Path(td) / 'b'
            a.mkdir(); b.mkdir()
            for n in demo.FILES:
                (a / n).write_bytes(b'original')
                (b / n).write_bytes(b'original')
            (b / 'sealed.bin').write_bytes(b'preserve me')
            self.assertTrue(demo.same_bundle(a, b))
            (a / 'initramfs.img').write_bytes(b'changed')
            self.assertFalse(demo.same_bundle(a, b))

if __name__ == '__main__':
    unittest.main()
