#!/usr/bin/env python3
"""Strict host selector test only; not real allocator/unwind/runtime proof."""
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory(prefix='dma-fault-selector-') as temporary:
    executable = Path(temporary) / 'test'
    subprocess.run(['clang', '-std=c11', '-O1', '-Wall', '-Wextra', '-Werror',
                    '-fsanitize=address,undefined',
                    str(ROOT / 'tools/stock-recovery/runtime-audit/test_audit_fault_plan.c'),
                    '-o', str(executable)], check=True)
    subprocess.run([str(executable)], check=True)
print('PASS: task/mm-scoped one-shot selector; NOT ENOMEM/unwind execution')
