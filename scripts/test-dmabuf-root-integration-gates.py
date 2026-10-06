#!/usr/bin/env python3
"""Unit tests for composition gates, not a replacement for a real root build."""
import argparse
import hashlib
from importlib.machinery import SourceFileLoader
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

module = SourceFileLoader('dma_root_driver', str(Path(__file__).with_name('integrate-dmabuf-after-root.py'))).load_module()


class Gates(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='dma-root-gates-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.names = ['fixture/' + str(i) + '.c' for i in range(26)]
        for name in self.names:
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(name + '\n')

    def test_ordered_manifest_matches_independent_bytes(self):
        content = b''.join(name.encode() + b'\0' + hashlib.sha256((self.root / name).read_bytes()).digest()
                           for name in sorted(self.names))
        self.assertEqual(module.ordered_manifest(self.root, list(reversed(self.names))), hashlib.sha256(content).hexdigest())
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            module.ordered_manifest(self.root, self.names + self.names[:1])
        with self.assertRaisesRegex(ValueError, 'unsafe'):
            module.ordered_manifest(self.root, ['../outside'])

    def test_root_manifest_count_hash_and_copied_source(self):
        # Synthetic constants are limited to this helper test. Production pins
        # are unchanged, and no root integration is claimed by this fixture.
        sha = module.ordered_manifest(self.root, self.names)
        copied = self.root / 'copied.c'
        copied.write_bytes(b'fixture copied source')
        with patch.object(module, 'changed', return_value=self.names), patch.object(module, 'ROOT_MANIFEST', sha), \
                patch.object(module, 'COPIED', {'copied.c': hashlib.sha256(copied.read_bytes()).hexdigest()}):
            self.assertEqual(module.root_gate(self.root), self.names)
            copied.write_bytes(b'drift')
            with self.assertRaisesRegex(ValueError, 'copied SUSFS'):
                module.root_gate(self.root)
        with patch.object(module, 'changed', return_value=self.names[:-1]):
            with self.assertRaisesRegex(ValueError, 'ordered manifest'):
                module.root_gate(self.root)
        with patch.object(module, 'changed', return_value=self.names):
            with self.assertRaisesRegex(ValueError, 'ordered manifest'):
                module.root_gate(self.root)

    def test_symlink_cannot_enter_manifest(self):
        path = self.root / self.names[0]
        path.unlink()
        path.symlink_to(self.root / self.names[1])
        with self.assertRaisesRegex(ValueError, 'symlink'):
            module.ordered_manifest(self.root, self.names)

    def args(self):
        return argparse.Namespace(source=self.root, ksu_source=self.root, susfs_source=self.root,
                                  fix_source=self.root, overlay=self.root, output=self.root / 'evidence.json')

    def test_wrong_head_does_not_invoke_integrator(self):
        with patch.object(module, 'git', return_value=b'wrong\n'), patch.object(module.subprocess, 'run') as command:
            with self.assertRaisesRegex(ValueError, 'HEAD mismatch'):
                module.run(self.args())
            command.assert_not_called()

    def test_dirty_checkout_does_not_invoke_integrator(self):
        with patch.object(module, 'git', side_effect=[(module.composition.validator.prepare.COMMIT + '\n').encode(), b' M mm/memory.c\n']), \
                patch.object(module.subprocess, 'run') as command:
            with self.assertRaisesRegex(ValueError, 'pristine'):
                module.run(self.args())
            command.assert_not_called()

    def test_existing_evidence_preserved(self):
        args = self.args()
        args.output.write_text('owned\n')
        with patch.object(module, 'git') as command:
            with self.assertRaisesRegex(ValueError, 'output unavailable'):
                module.run(args)
            command.assert_not_called()
        self.assertEqual(args.output.read_text(), 'owned\n')

    def test_manager_compatibility_pins(self):
        replies = [(value + '\n').encode() for value in (module.KSU_PIN, module.KSU_UAPI, module.KSU_NATIVES)]
        replies += [b'', b'const val MINIMAL_SUPPORTED_KERNEL = 33188\n']
        with patch.object(module, 'git', side_effect=replies) as command:
            module.ksu_compatibility_gate(self.root)
            self.assertIn(unittest.mock.call(self.root, 'merge-base', '--is-ancestor', module.KSU_V330, module.KSU_PIN), command.call_args_list)
        for index in (0, 1, 2, 4):
            changed = list(replies)
            changed[index] = b'wrong\n'
            with patch.object(module, 'git', side_effect=changed):
                with self.assertRaisesRegex(ValueError, 'mismatch'):
                    module.ksu_compatibility_gate(self.root)


if __name__ == '__main__':
    unittest.main()
