#!/usr/bin/env python3
import argparse
from importlib.machinery import SourceFileLoader
from pathlib import Path
import tempfile
import unittest

module = SourceFileLoader('dma_root_fragment', str(Path(__file__).with_name('prepare-dmabuf-root-fragment.py'))).load_module()
repo = Path(__file__).parents[1]


class Fragment(unittest.TestCase):
    def test_pinned_inputs_preserve_all_root_values(self):
        with tempfile.TemporaryDirectory(prefix='dma-fragment-') as temp:
            args = argparse.Namespace(root=repo / 'configs/rodin-6.6.77-ksun-susfs.fragment',
                                      dma=repo / 'tools/stock-recovery/overlays/dma-6.6.77/enabled.fragment', output=Path(temp) / 'fragment')
            module.run(args)
            root = module.settings(args.root.read_text())
            actual = module.settings(args.output.read_text())
            self.assertEqual(actual, dict(root, CONFIG_TRANSPARENT_HUGEPAGE='y', CONFIG_XIAOMI_DMABUF_HUGETLB='y'))
            with self.assertRaises(FileExistsError):
                module.run(args)

    def test_duplicate_and_overlap_rejected(self):
        for text in ('CONFIG_KSU=y\nCONFIG_KSU=n\n', 'CONFIG_KSU=y\n# CONFIG_KSU is not set\n'):
            with self.assertRaisesRegex(ValueError, 'duplicate'):
                module.settings(text)
        with self.assertRaisesRegex(ValueError, 'overlap'):
            module.combine('CONFIG_TRANSPARENT_HUGEPAGE=n\n', 'CONFIG_TRANSPARENT_HUGEPAGE=y\nCONFIG_XIAOMI_DMABUF_HUGETLB=y\n')

    def test_extra_delta_and_malformed_rejected(self):
        with self.assertRaisesRegex(ValueError, 'delta'):
            module.combine('CONFIG_KSU=y\n', 'CONFIG_TRANSPARENT_HUGEPAGE=y\nCONFIG_XIAOMI_DMABUF_HUGETLB=y\nCONFIG_MODULE_SIG_PROTECT=n\n')
        with self.assertRaisesRegex(ValueError, 'malformed'):
            module.settings('CONFIG_KSU\n')

    def test_pin_drift_has_no_output(self):
        with tempfile.TemporaryDirectory(prefix='dma-fragment-') as temp:
            temp = Path(temp)
            root = temp / 'root';root.write_text('CONFIG_KSU=y\n')
            args = argparse.Namespace(root=root, dma=repo / 'tools/stock-recovery/overlays/dma-6.6.77/enabled.fragment', output=temp / 'out')
            with self.assertRaisesRegex(ValueError, 'pin drift'):
                module.run(args)
            self.assertFalse(args.output.exists())


if __name__ == '__main__':
    unittest.main()
