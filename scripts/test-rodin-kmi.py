#!/usr/bin/env python3
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('align', Path(__file__).with_name('align-rodin-kmi.py'))
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class KmiAlignment(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root / 'android').mkdir()
        self.kmi = self.root / 'android/abi_gki_aarch64_pixel'
        self.original = '[abi_symbol_list]\n  keep_me\n' + ''.join(
            f'  {s}\n' for s in sorted(mod.SYMBOLS))
        self.kmi.write_text(self.original)
        self.ref = self.root / 'reference.json'
        self.ref.write_text(json.dumps({'kernel_import_crcs': {'keep_me': 1}}))
        self.fragment = self.root / 'fragment'
        self.fragment.write_text('# CONFIG_USB_XHCI_SIDEBAND is not set\n')

    def test_only_six_removed(self):
        mod.align(self.root, self.ref, self.fragment)
        self.assertEqual(self.kmi.read_text(), '[abi_symbol_list]\n  keep_me\n')

    def test_required_export_blocks_all_writes(self):
        self.ref.write_text(json.dumps({'kernel_import_crcs': {'xhci_sideband_register': 1}}))
        with self.assertRaisesRegex(ValueError, 'ROM requires'):
            mod.align(self.root, self.ref, self.fragment)
        self.assertEqual(self.kmi.read_text(), self.original)

    def test_enabled_feature_blocks(self):
        self.fragment.write_text('CONFIG_USB_XHCI_SIDEBAND=y\n')
        with self.assertRaisesRegex(ValueError, 'disabled'):
            mod.align(self.root, self.ref, self.fragment)
        self.assertEqual(self.kmi.read_text(), self.original)

    def test_source_drift_blocks_all_writes(self):
        before = self.original.replace('  xhci_sideband_register\n', '')
        self.kmi.write_text(before)
        with self.assertRaisesRegex(ValueError, 'source symbol set'):
            mod.align(self.root, self.ref, self.fragment)
        self.assertEqual(self.kmi.read_text(), before)


if __name__ == '__main__':
    unittest.main()
