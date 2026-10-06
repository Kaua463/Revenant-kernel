#!/usr/bin/env python3
"""Reject unexpected composed inputs before applying the DMA review patch."""
import argparse
from importlib.machinery import SourceFileLoader
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

module = SourceFileLoader('dma_composed', str(Path(__file__).with_name('validate-dmabuf-susfs-overlay.py'))).load_module()
ARGS = None


class Composition(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='dma-composed-test-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source = self.root / 'source'
        self.reference = self.root / 'reference'
        self.overlay = self.root / 'overlay'
        shutil.copytree(ARGS.ack_reference, self.reference)
        shutil.copytree(ARGS.ack_reference, self.source)
        shutil.copytree(ARGS.overlay, self.overlay)
        patch = subprocess.run(['git', '-C', str(ARGS.susfs_source), 'show', module.PIN + ':' + module.PATCH_PATH], check=True, capture_output=True).stdout
        path = self.root / 'susfs.patch'
        path.write_bytes(patch)
        module.apply(self.source, path, include='mm/memory.c')
        self.args = argparse.Namespace(source=self.source, ack_reference=self.reference, overlay=self.overlay,
                                       susfs_source=ARGS.susfs_source, apply_review=False, output=None)

    def test_dry_run_apply_repeat(self):
        initial = (self.source / 'mm/memory.c').read_bytes()
        report = module.run(self.args)
        self.assertFalse(report['applied'])
        self.assertEqual(initial, (self.source / 'mm/memory.c').read_bytes())
        self.assertNotEqual(report['before']['mm/memory.c'], module.validator.prepare.SOURCES['mm/memory.c'])
        self.args.apply_review = True
        report = module.run(self.args)
        for name, sha in report['after'].items():
            self.assertEqual(module.digest((self.source / name).read_bytes()), sha)
        with self.assertRaisesRegex(ValueError, 'preimage drift'):
            module.run(self.args)

    def test_unexpected_input_rejected_before_write(self):
        for name in ('mm/memory.c', 'include/linux/mm_types.h'):
            path = self.source / name
            original = path.read_bytes()
            path.write_bytes(original + b'/* unexpected edit */\n')
            self.args.apply_review = True
            with self.assertRaisesRegex(ValueError, 'preimage drift'):
                module.run(self.args)
            self.assertFalse((self.source / module.HEADER).exists())
            self.assertEqual(path.read_bytes(), original + b'/* unexpected edit */\n')
            path.write_bytes(original)

    def test_reference_drift_rejected(self):
        path = self.reference / 'mm/memory.c'
        path.write_bytes(path.read_bytes() + b'\n')
        with self.assertRaisesRegex(ValueError, 'reference drift'):
            module.run(self.args)

    def test_patch_drift_rejected(self):
        path = self.overlay / 'dmabuf-review.patch'
        path.write_bytes(path.read_bytes() + b'\n')
        with self.assertRaisesRegex(ValueError, 'patch hash mismatch'):
            module.run(self.args)

    def test_existing_header_and_symlink_rejected(self):
        path = self.source / module.HEADER
        path.write_text('owned header\n')
        with self.assertRaisesRegex(ValueError, 'already exists'):
            module.run(self.args)
        self.assertEqual(path.read_text(), 'owned header\n')
        memory = self.source / 'mm/memory.c'
        memory.unlink()
        memory.symlink_to(self.reference / 'mm/memory.c')
        with self.assertRaisesRegex(ValueError, 'symlink'):
            module.run(self.args)

    def test_evidence_no_overwrite_before_apply(self):
        self.args.output = self.root / 'evidence.json'
        self.args.apply_review = True
        self.args.output.write_text('owned evidence\n')
        with self.assertRaisesRegex(ValueError, 'output already exists'):
            module.run(self.args)
        self.assertEqual(self.args.output.read_text(), 'owned evidence\n')
        self.assertFalse((self.source / module.HEADER).exists())


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('ack-reference', 'overlay', 'susfs-source'):
        parser.add_argument('--' + name, type=Path, required=True)
    ARGS = parser.parse_args()
    unittest.main(argv=[__file__])
