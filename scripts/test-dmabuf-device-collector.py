#!/usr/bin/env python3
"""Command/quoting policy only; never connects ADB."""
from importlib.machinery import SourceFileLoader
from pathlib import Path
import shlex
import unittest

m = SourceFileLoader('collector_policy_test', str(Path(__file__).with_name('collect-dmabuf-device-evidence.py'))).load_module()


class Commands(unittest.TestCase):
    def test_no_personal_reads_or_device_writes(self):
        for recovery in (True, False):
            for name, command in m.jobs(recovery):
                self.assertEqual(command[:2], ['adb', 'shell'])
                payload = command[2]
                for token in ('/sdcard', '/data', 'logcat', 'setenforce', 'reboot', 'mount ', 'dd ',
                              'pm list', 'dumpsys', '/proc/self/mem', ' > ', 'rm ', 'echo '):
                    self.assertNotIn(token, payload)
                if not recovery and name.endswith('filtered'):
                    parsed = shlex.split(payload)
                    self.assertEqual(parsed[:2], ['su', '-c'])
                    self.assertEqual(len(parsed), 3)
                    self.assertIn(m.PATTERN, parsed[2])


if __name__ == '__main__':
    unittest.main()
