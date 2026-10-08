#!/usr/bin/env python3
"""Pinned source test requires real cached ACK files; no modeled kernel pass."""
from importlib.machinery import SourceFileLoader
from pathlib import Path
import unittest
import tempfile
import subprocess
from types import SimpleNamespace

m = SourceFileLoader('vma_fault_test', str(Path(__file__).with_name('prepare-dmabuf-vma-fault-sites.py'))).load_module()
ROOT = Path(__file__).resolve().parents[3] / 'outputs'


class FaultSites(unittest.TestCase):
    def test_real_preimages_and_disabled_allocator(self):
        files = {'mm/mmap.c': ROOT / 'stock-ack-dmabuf-overlay-reference-20261005/mm/mmap.c',
                 'kernel/fork.c': ROOT / 'stock-ack-dma-vma-free-reference-20261006/kernel/fork.c'}
        # mmap.c's input is the canonical root+DMA postimage, not pristine ACK.
        validator = SourceFileLoader('vma_overlay_test', str(Path(__file__).with_name('validate-dmabuf-overlay.py'))).load_module()
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            subprocess.run(['git', 'init', '-q', str(folder)], check=True)
            for name in validator.prepare.SOURCES:
                path = folder / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes((ROOT / 'stock-ack-dmabuf-overlay-reference-20261005' / name).read_bytes())
            validator.run(SimpleNamespace(source=folder,
                overlay=Path(__file__).resolve().parents[1] / 'tools/stock-recovery/overlays/dma-6.6.77', apply_review=True))
            mmap_postimage = (folder / 'mm/mmap.c').read_bytes()
        for name, path in files.items():
            before = path.read_bytes()
            if name == 'mm/mmap.c':
                before = mmap_postimage
            after = m.transform(name, before)
            self.assertIn(b'#ifdef CONFIG_XIAOMI_DMABUF_RUNTIME_AUDIT', after)
            self.assertIn(b'#else', after)
            self.assertEqual(after.count(b'recovered_dma_audit_vma_fail('), 3 if name.startswith('mm/') else 2)
            with self.assertRaises(ValueError):
                m.transform(name, before + b'\n')
            with self.assertRaises(ValueError):
                m.transform(name, after)


if __name__ == '__main__':
    unittest.main()
