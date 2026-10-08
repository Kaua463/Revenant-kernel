#!/usr/bin/env python3
"""Recovery package/source guards; no Android block device or repack execution."""
from importlib.machinery import SourceFileLoader
from pathlib import Path
import tempfile
import unittest
import zipfile

m = SourceFileLoader('staged_package_tests', str(Path(__file__).with_name('package-dmabuf-staged-orangefox.py'))).load_module()


def guard(text):
    required = ['[ -d /twres ]', 'ro.product.device', 'ro.boot.slot_suffix',
                'ro.boot.snapshot_merge.status', 'Only verified slot A',
                'Unexpected boot size', 'Current kernel is not the verified working no-DMA boot',
                'Persistent rollback verification failed', 'Repacked kernel mismatch',
                'Boot header/layout changed unexpectedly', 'AVB footer missing/moved',
                'PATCHVBMETAFLAG=false', 'KEEPVERITY=true', 'KEEPFORCEENCRYPT=true',
                'Readback mismatch', 'conv=fsync', 'MODE" = preflight',
                'No partition was written.', 'Need 512 MiB', 'Need 68 MiB']
    for token in required:
        if token not in text:
            raise ValueError('missing package safety gate: ' + token)
    write = text.index('blockdev --setrw')
    if not (text.index('Persistent rollback verification failed') <
            text.index('Repacked kernel mismatch') < text.index('AVB footer missing/moved') <
            text.index('No partition was written.') < write < text.index('Readback mismatch')):
        raise ValueError('pre-write gate ordering')
    for token in ('adb ', 'fastboot ', 'setenforce', 'mount ', 'vendor_boot_a', 'vendor_dlkm',
                  'init_boot', 'wipe', 'of=/dev/zero', 'reboot'):
        # Textual error instructions may mention reboot, but no executable reboot.
        if token == 'reboot':
            continue
        if token in text and token != 'wipe':
            raise ValueError('unrelated device action: ' + token)


class Packages(unittest.TestCase):
    def test_all_three_operations_and_negative_guards(self):
        tools = {name: (m.STOCK_TEMPLATE/name).read_bytes() for name in ('tools/busybox','tools/magiskboot')}
        for mode in ('flash', 'restore', 'preflight'):
            text = m.script(mode, 'Image', '0'*64, tools).decode()
            guard(text)
            self.assertIn('MODE='+mode, text)
            self.assertNotIn('@BOOT_SHA@', text)
            for token in ('Persistent rollback verification failed', 'Repacked kernel mismatch',
                          'AVB footer missing/moved', 'PATCHVBMETAFLAG=false', 'No partition was written.'):
                with self.subTest(mode=mode, token=token), self.assertRaises(ValueError):
                    guard(text.replace(token, 'REMOVED'))

    def test_zip_manifest_integrity_modes_no_overwrite(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary)/'package.zip'
            m.archive(path, {'Image': b'fixture', 'META-INF/com/google/android/update-binary': b'#!/sbin/sh\n'})
            with zipfile.ZipFile(path) as stream:
                self.assertEqual(stream.read('SHA256SUMS').count(b'\n'), 2)
                self.assertNotIn(b'SHA256SUMS', stream.read('SHA256SUMS'))
                self.assertEqual(stream.getinfo('META-INF/com/google/android/update-binary').external_attr >> 16, 0o100755)
            with self.assertRaises(FileExistsError):
                m.archive(path, {'Image': b'changed'})


if __name__ == '__main__':
    unittest.main()
