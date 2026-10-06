#!/usr/bin/env python3
"""Sanitized host test of guest data oracle, not DMA or guest execution."""
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1] / 'tools/stock-recovery/runtime-audit'
with tempfile.TemporaryDirectory(prefix='dma-guest-data-') as temporary:
    binary = Path(temporary) / 'test'
    subprocess.run(['clang', '-std=c11', '-O1', '-Wall', '-Wextra', '-Werror',
                    '-fsanitize=address,undefined', str(root / 'test_audit_data.c'),
                    '-o', str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
