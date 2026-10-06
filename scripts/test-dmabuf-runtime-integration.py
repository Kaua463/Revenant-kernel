#!/usr/bin/env python3
"""Pinned producer integration tests in disposable fixtures; no Kbuild/device."""
from importlib.machinery import SourceFileLoader
from pathlib import Path
import os
import shutil
import subprocess
import tempfile
from types import SimpleNamespace
import unittest

ROOT = Path(__file__).resolve().parents[1]
module = SourceFileLoader('runtime_integrator', str(ROOT / 'scripts/prepare-dmabuf-runtime-audit.py')).load_module()
REFERENCE = Path(os.environ.get('DMA_ACK_REFERENCE', str(ROOT.parent.parent / 'outputs/stock-ack-dmabuf-overlay-reference-20261005')))


class Integration(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='dma-runtime-integration-')
        self.addCleanup(self.temp.cleanup)
        self.folder = Path(self.temp.name)
        self.source = self.folder / 'source'
        self.reference = self.folder / 'reference'
        self.source.mkdir()
        self.reference.mkdir()
        for name in module.validator.prepare.SOURCES:
            for target in (self.source, self.reference):
                (target / name).parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(REFERENCE / name, target / name)
        overlay = ROOT / 'tools/stock-recovery/overlays/dma-6.6.77'
        module.validator.run(SimpleNamespace(source=self.source, overlay=overlay, apply_review=True))
        self.args = SimpleNamespace(source=self.source, ack_reference=self.reference,
                                    overlay=overlay, output=None, apply_review=False)

    def test_dry_run_apply_and_repeat(self):
        before = (self.source / 'mm/Kconfig').read_bytes()
        huge_before = (self.source / 'mm/huge_memory.c').read_bytes()
        report = module.run(self.args)
        self.assertEqual(len(report['changes']), 10)
        self.assertEqual((self.source / 'mm/Kconfig').read_bytes(), before)
        self.assertEqual((self.source / 'mm/huge_memory.c').read_bytes(), huge_before)
        self.assertFalse((self.source / 'mm/recovered-dma-audit').exists())
        self.args.apply_review = True
        module.run(self.args)
        self.assertEqual((self.source / 'mm/recovered-dma-audit/recovered-dma-audit.c').read_bytes(),
                         (ROOT / 'tools/stock-recovery/runtime-audit/recovered-dma-audit.c').read_bytes())
        self.assertEqual((self.source / 'mm/huge_memory.c').read_text().count(
                         'if (recovered_dma_audit_fail_alloc(mm, map_type))'), 2)
        with self.assertRaises(ValueError):
            module.run(self.args)

    def test_reference_inside_unrelated_git_repository(self):
        # Runner reference is a subfolder of the workflow checkout; git apply
        # must not silently filter paths against that unrelated Git prefix.
        subprocess.run(['git', 'init', '-q', str(self.folder)], check=True)
        report = module.run(self.args)
        self.assertEqual(len(report['changes']), 10)

    def test_target_drift_no_write(self):
        (self.source / 'mm/memory.c').write_text('drift')
        self.args.apply_review = True
        with self.assertRaises(ValueError):
            module.run(self.args)
        self.assertFalse((self.source / 'mm/recovered-dma-audit').exists())

    def test_reference_drift(self):
        (self.reference / 'mm/Makefile').write_text('drift')
        with self.assertRaises(ValueError):
            module.run(self.args)

    def test_existing_destination(self):
        (self.source / 'mm/recovered-dma-audit').mkdir()
        with self.assertRaises(ValueError):
            module.run(self.args)

    def test_symlink(self):
        (self.source / 'mm/recovered-dma-audit').symlink_to(self.folder / 'missing')
        with self.assertRaises(ValueError):
            module.run(self.args)

    def test_evidence_preserved(self):
        self.args.output = self.folder / 'evidence.json'
        self.args.output.write_text('owned')
        self.args.apply_review = True
        with self.assertRaises(ValueError):
            module.run(self.args)
        self.assertEqual(self.args.output.read_text(), 'owned')
        self.assertFalse((self.source / 'mm/recovered-dma-audit').exists())


if __name__ == '__main__':
    unittest.main()
