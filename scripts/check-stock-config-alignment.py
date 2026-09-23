#!/usr/bin/env python3
"""Check implemented config alignment, not full Xiaomi feature parity."""
from pathlib import Path
import sys

EXPECTED = {
    'CONFIG_PM_USERSPACE_AUTOSLEEP': 'y',
    'CONFIG_USB_XHCI_SIDEBAND': 'n',
    'CONFIG_LTO_NONE': 'y',
    'CONFIG_LTO_CLANG_THIN': 'n',
}


def validate(text):
    values = {}
    for line in text.splitlines():
        if line.startswith('CONFIG_') and '=' in line:
            key, value = line.split('=', 1)
        elif line.startswith('# CONFIG_') and line.endswith(' is not set'):
            key, value = line[2:-11], 'n'
        else:
            continue
        if key in values:
            raise ValueError(f'Duplicate setting: {key}')
        values[key] = value
    for key, value in EXPECTED.items():
        if values.get(key) != value:
            raise ValueError(f'{key}: expected {value}, got {values.get(key)}')
    for key in ('CONFIG_LTO', 'CONFIG_LTO_CLANG', 'CONFIG_LTO_CLANG_FULL'):
        if values.get(key, 'n') != 'n':
            raise ValueError(f'{key}: LTO must be disabled')


if __name__ == '__main__':
    validate(Path(sys.argv[1]).read_text())
    print('Implemented stock config alignment passed; missing Xiaomi extensions are NOT validated by this check.')
