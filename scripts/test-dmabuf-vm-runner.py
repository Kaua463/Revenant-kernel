#!/usr/bin/env python3
"""Runner failure/command policy tests; no QEMU invocation."""
from importlib.machinery import SourceFileLoader
from pathlib import Path
import json
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

module = SourceFileLoader('dma_vm_runner', str(Path(__file__).with_name('run-dmabuf-vm-audit.py'))).load_module()
PASS = '\n'.join(('DMA_GUEST_CASE_PASS: /dev/recovered-dma-audit-pmd reader_passes=1',
                  'DMA_GUEST_CASE_PASS: /dev/recovered-dma-audit-pte reader_passes=1',
                  'DMA_GUEST_PASS: basic tests', 'DMA_VM_RESULT_PASS: finished'))


class Runner(unittest.TestCase):
    def fixture(self, folder):
        image = bytearray(64)
        image[56:60] = b'ARMd'
        (folder/'Image').write_bytes(image)
        (folder/'config').write_text('\n'.join('CONFIG_' + name + '=y' for name in module.REQUIRED))
        (folder/'initramfs').write_bytes(b'070701')
        return SimpleNamespace(kernel=folder/'Image', config=folder/'config',
                               initramfs=folder/'initramfs', output=folder/'evidence', timeout=30)

    def test_mock_process_success_and_refuse_overwrite(self):
        with tempfile.TemporaryDirectory(prefix='dma-vm-runner-test-') as temporary:
            args = self.fixture(Path(temporary))
            result = subprocess.CompletedProcess([], 0, stdout=PASS.encode())
            with patch.object(module.subprocess, 'run', return_value=result) as process:
                module.run(args)
                self.assertEqual(process.call_args.kwargs['timeout'], 30)
                with self.assertRaises(ValueError):
                    module.run(args)
                self.assertEqual(process.call_count, 1)
            self.assertEqual(json.loads((args.output/'report.json').read_text())['status'],
                             'BASIC_GUEST_WORKLOAD_PASS_NOT_FULL_DMA_PROOF')

    def test_timeout_and_nonzero_preserve_failure(self):
        for failure in (subprocess.CompletedProcess([], 1, stdout=PASS.encode()),
                        subprocess.TimeoutExpired([], 30, output=b'boot still running')):
            with tempfile.TemporaryDirectory(prefix='dma-vm-runner-test-') as temporary:
                args = self.fixture(Path(temporary))
                parameters = {'side_effect': failure} if isinstance(failure, Exception) else {'return_value': failure}
                with patch.object(module.subprocess, 'run', **parameters), self.assertRaises(RuntimeError):
                    module.run(args)
                report = json.loads((args.output/'report.json').read_text())
                self.assertEqual(report['status'], 'GUEST_FAILED')
                self.assertTrue(report['failure'])
                self.assertTrue((args.output/'serial.log').exists())

    def test_markers_and_errors(self):
        module.check_log(PASS)
        for marker in ('DMA_GUEST_CASE_PASS:', 'DMA_GUEST_PASS:', 'DMA_VM_RESULT_PASS:'):
            with self.subTest(marker=marker), self.assertRaises(ValueError):
                module.check_log(PASS.replace(marker, 'missing', 1))
        for error in ('DMA_GUEST_FAIL: x', 'DMA_VM_RESULT_FAIL: x', 'BUG: x',
                      'WARNING: x', 'Oops: x', 'Kernel panic', 'Call trace:'):
            with self.subTest(error=error), self.assertRaises(ValueError):
                module.check_log(PASS + '\n' + error)
        with self.assertRaises(ValueError):
            module.check_log(PASS + '\nDMA_GUEST_PASS: duplicate')

    def test_config_gate(self):
        config = '\n'.join('CONFIG_' + name + '=y' for name in module.REQUIRED)
        module.check_config(config)
        for name in module.REQUIRED:
            with self.subTest(name=name), self.assertRaises(ValueError):
                module.check_config(config.replace('CONFIG_' + name + '=y', 'CONFIG_' + name + '=m'))

    def test_ram_only_command(self):
        args = SimpleNamespace(kernel=Path('/tmp/audit/Image'), initramfs=Path('/tmp/audit/initramfs.cpio'))
        cmd = module.command(args)
        self.assertEqual(cmd[0], 'qemu-system-aarch64')
        for flag in ('-monitor', '-nic'):
            self.assertEqual(cmd[cmd.index(flag) + 1], 'none')
        self.assertEqual(cmd[cmd.index('-smp') + 1], '4')
        self.assertFalse(any(word in cmd for word in ('-drive', '-hda', '-device', '-netdev', '-virtfs')))


if __name__ == '__main__':
    unittest.main()
