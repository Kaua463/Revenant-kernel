#!/usr/bin/env python3
"""Compile actual audit log expressions with printf type checking, not kernel mocks."""
from pathlib import Path
import re
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1] / 'tools/stock-recovery/runtime-audit'


def compile_logs(source):
    structure = re.search(r'struct audit_buffer \{.*?\n\};', source, re.S)
    size = re.search(r'^#define AUDIT_BYTES .*$', source, re.M)
    logs = re.findall(r'\bpr_(?:info|err)\((.*?)\);', source, re.S)
    if not structure or not size or len(logs) != 8:
        raise ValueError('unexpected audit format inventory')
    program = '''#include <stdbool.h>
#include "audit-map-contract.h"
#include "audit-fault-plan.h"
void checked_log(const char *, ...) __attribute__((format(printf, 1, 2)));
''' + structure.group(0) + '\n' + size.group(0) + '''
void check_logs(void) {
    struct audit_buffer storage = {0}, *buffer = &storage;
    struct dma_audit_fault_plan audit_fault_plan = {0};
    long long published = 0;
    unsigned long long audit_fault_id = 0, id = 0;
    unsigned int map_type = 0, table_present = 0;
    unsigned long table_bytes_retry = 0;
    int result = 0;
''' + '\n'.join('checked_log(' + log + ');' for log in logs) + '\n}\n'
    return subprocess.run(['clang', '-x', 'c', '-std=c11', '-Wall', '-Wextra',
                           '-Werror', '-Wformat', '-fsyntax-only', '-I', str(ROOT), '-'],
                          input=program, text=True, capture_output=True, check=False)


class Formats(unittest.TestCase):
    def setUp(self):
        self.source = (ROOT / 'recovered-dma-audit.c').read_text()

    def test_all_actual_log_expressions(self):
        result = compile_logs(self.source)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_unsigned_long_long_size_regression_fails(self):
        result = compile_logs(self.source.replace('(unsigned long)AUDIT_BYTES', 'AUDIT_BYTES'))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('format specifies type', result.stderr)

    def test_other_log_identity_type_regression_fails(self):
        result = compile_logs(self.source.replace('id=%llu', 'id=%u', 1))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('format specifies type', result.stderr)


if __name__ == '__main__':
    unittest.main()
