#!/usr/bin/env python3
"""Root-VM preimage/ownership gates; fixtures are not a real root build."""
import argparse
from importlib.machinery import SourceFileLoader
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

m = SourceFileLoader('test_root_runtime', str(Path(__file__).with_name('prepare-dmabuf-root-runtime.py'))).load_module()


class RootRuntime(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.folder = Path(self.temp.name)
        self.source = self.folder / 'source'
        self.source.mkdir()
        for i in range(31):
            (self.source / f'path{i}').write_text(f'fixture{i}')
        self.names = [f'path{i}' for i in range(31)]
        self.sha = m.root.ordered_manifest(self.source, self.names)
        self.pin = patch.object(m.root, 'COMPOSED_MANIFEST', self.sha)
        self.pin.start()
        self.addCleanup(self.pin.stop)
        self.report = {'ack_commit': m.root.composition.validator.prepare.COMMIT,
                       'composed_tracked_paths': self.names,
                       'composed_tracked_manifest_sha256': self.sha, 'after': {}}
        for name, sha in m.root.COPIED.items():
            target = self.source / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(b'fixture')
        self.copied = patch.object(m.root, 'COPIED', {name: m.runtime.digest(b'fixture') for name in m.root.COPIED})
        self.copied.start()
        self.addCleanup(self.copied.stop)

    def test_complete_ordered_manifest(self):
        m.validate_composition(self.source, self.report)

    def test_actual_source_drift_rejected(self):
        (self.source / 'path0').write_text('changed')
        with self.assertRaisesRegex(ValueError, 'actual root'):
            m.validate_composition(self.source, self.report)

    def test_identity_count_and_duplicate_path_rejected(self):
        for field, value in [('ack_commit', 'wrong'), ('composed_tracked_manifest_sha256', 'wrong'),
                             ('composed_tracked_paths', self.names[:-1]),
                             ('composed_tracked_paths', self.names[:-1] + [self.names[0]])]:
            with self.subTest(field=field), self.assertRaises(ValueError):
                m.validate_composition(self.source, dict(self.report, **{field: value}))

    def test_copied_and_untracked_header_drift_rejected(self):
        (self.source / 'extra').write_text('changed')
        self.report['after']['extra'] = m.runtime.digest(b'expected')
        with self.assertRaisesRegex(ValueError, 'copied/DMA'):
            m.validate_composition(self.source, self.report)

    def test_source_symlink_rejected(self):
        target = self.source / self.names[0]
        target.unlink()
        target.symlink_to(self.source / self.names[1])
        with self.assertRaises(ValueError):
            m.validate_composition(self.source, self.report)

    def test_instrumentation_preserves_root_paths_and_rejects_repeat(self):
        # Canonical huge_memory source, not a substitute implementation.
        reference = m.runtime.ROOT.parents[1] / 'outputs/stock-dmabuf-overlay-20261006-v9/candidate/mm/huge_memory.c'
        (self.source / 'mm').mkdir()
        shutil.copyfile(reference, self.source / 'mm/huge_memory.c')
        for name in ['mm/Kconfig', 'mm/Makefile']:
            (self.source / name).write_text('root fixture preserved\n')
        composition = self.folder / 'composition.json'
        composition.write_text(json.dumps(self.report))
        args = argparse.Namespace(source=self.source, composition=composition, output=self.folder / 'result.json')
        m.run(args)
        self.assertEqual((self.source / 'path0').read_text(), 'fixture0')
        self.assertTrue((self.source / 'mm/Kconfig').read_text().startswith('root fixture preserved\n'))
        self.assertTrue((self.source / 'mm/recovered-dma-audit/recovered-dma-export-audit.c').is_file())
        with self.assertRaisesRegex(ValueError, 'already exists'):
            m.run(args)


if __name__ == '__main__':
    unittest.main()
