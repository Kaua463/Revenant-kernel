#!/usr/bin/env python3
"""Exact seven-file composition, disabled semantics, preflight and patch round-trip."""
import argparse
import hashlib
from importlib.machinery import SourceFileLoader
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
combined = SourceFileLoader('dma_combined', str(HERE/'prepare-dmabuf-combined-overlay.py')).load_module()
base_test = SourceFileLoader('dma_base_test', str(HERE/'test-prepare-dmabuf-reimplementation.py')).load_module()
ARGS = None


class Composition(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='dma-composition-test-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.args = argparse.Namespace(**vars(ARGS), output=self.root/'combined')

    def test_pinned_roundtrip_disabled_and_no_exports(self):
        combined.run(self.args)
        out = self.args.output
        report = json.loads((out/'manifest.json').read_text())
        self.assertEqual(report['status'], 'REVIEW_ONLY_NOT_INSTALLABLE')
        self.assertEqual(len(report['changes']), 7)
        self.assertEqual(report['safety_deviations'], combined.base.SAFETY_DEVIATIONS)
        tree = self.root/'tree'
        shutil.copytree(ARGS.source, tree)
        target = tree/combined.address.PATH
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ARGS.core, target)
        patch = out/'dmabuf-combined-review.patch'
        self.assertEqual(hashlib.sha256(patch.read_bytes()).hexdigest(), report['patch_sha256'])
        for operation in (['--check'], []):
            subprocess.run(['git', 'apply', *operation, str(patch)], cwd=tree, check=True,
                           capture_output=True)
        for name, record in report['changes'].items():
            self.assertEqual(hashlib.sha256((tree/name).read_bytes()).hexdigest(), record['after'])
        core = target.read_text()
        original = ARGS.core.read_text()
        self.assertEqual(base_test.disabled(core).replace('\n\n'+combined.address.FOPS,
                                                         '\n'+combined.address.FOPS), original)
        self.assertEqual(core.count('EXPORT_SYMBOL'), original.count('EXPORT_SYMBOL'))
        self.assertEqual(core.count('.get_unmapped_area = dma_buf_hugetlb_get_unmapped_area,'), 1)
        huge = (tree/'mm/huge_memory.c').read_text()
        self.assertIn('if (!next)\n\t\t\treturn;', huge)
        for name in ('mm/memory.c', 'mm/mmap.c', 'mm/mremap.c', 'mm/huge_memory.c'):
            self.assertEqual(base_test.disabled((tree/name).read_text()).rstrip('\n'),
                             (ARGS.source/name).read_text().rstrip('\n'))
        subprocess.run(['git', 'apply', '--reverse', str(patch)], cwd=tree, check=True,
                       capture_output=True)
        self.assertEqual(target.read_bytes(), ARGS.core.read_bytes())
        for name in combined.base.SOURCES:
            self.assertEqual((tree/name).read_bytes(), (ARGS.source/name).read_bytes())
        self.assertFalse((tree/'include/linux/xiaomi_dmabuf_huge.h').exists())

    def test_core_drift_leaves_no_final_output(self):
        core = self.root/'bad-core.c'
        core.write_bytes(ARGS.core.read_bytes()+b'/* drift */\n')
        self.args.core = core
        with self.assertRaisesRegex(ValueError, 'core drift'):
            combined.run(self.args)
        self.assertFalse(self.args.output.exists())

    def test_existing_output_preserved(self):
        self.args.output.mkdir()
        marker = self.args.output/'user-owned'
        marker.write_text('keep')
        with self.assertRaisesRegex(ValueError, 'must not exist'):
            combined.run(self.args)
        self.assertEqual(marker.read_text(), 'keep')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('source', 'core', 'image', 'symbols'):
        parser.add_argument('--'+name, type=Path, required=True)
    ARGS = parser.parse_args()
    unittest.main(argv=[__file__])
