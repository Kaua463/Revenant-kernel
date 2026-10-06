#!/usr/bin/env python3
"""Compile/run audit producer scalar preflight under ASan/UBSan; no device."""
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).parents[1] / 'tools/stock-recovery/runtime-audit'
with tempfile.TemporaryDirectory(prefix='dma-audit-preflight-') as temporary:
    binary = Path(temporary) / 'test'
    subprocess.run(['clang', '-std=c11', '-Wall', '-Wextra', '-Werror', '-fsanitize=address,undefined',
                    str(root / 'test_audit_map_contract.c'), '-o', str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
