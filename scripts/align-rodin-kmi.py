#!/usr/bin/env python3
"""Exclude only disabled XHCI sideband exports from the rodin KMI target."""
import json
from pathlib import Path
import sys

SYMBOLS = frozenset('xhci_sideband_' + suffix for suffix in (
    'add_endpoint', 'create_interrupter', 'register', 'remove_endpoint',
    'remove_interrupter', 'unregister'))


def align(root, reference, fragment):
    required = json.loads(reference.read_text())['kernel_import_crcs']
    if SYMBOLS.intersection(required):
        raise ValueError('ROM requires XHCI sideband exports')
    settings = [line.strip() for line in fragment.read_text().splitlines()
                if 'CONFIG_USB_XHCI_SIDEBAND' in line]
    if settings != ['# CONFIG_USB_XHCI_SIDEBAND is not set']:
        raise ValueError('Expected XHCI sideband disabled')
    edits = []
    found = set()
    for path in [root / 'android/abi_gki_aarch64_pixel']:
        if not path.is_file():
            continue
        lines = path.read_text().splitlines(keepends=True)
        matches = {line.strip() for line in lines} & SYMBOLS
        if matches:
            found.update(matches)
            edits.append((path, ''.join(line for line in lines
                                       if line.strip() not in SYMBOLS)))
    if found != SYMBOLS:
        raise ValueError(f'Unexpected source symbol set: {sorted(found)}')
    for path, text in edits:
        path.write_text(text)
        print(f'Adjusted disabled sideband entries: {path.name}')
    print('Six unused sideband symbols excluded; strict KMI checks remain enabled')


if __name__ == '__main__':
    repo = Path(__file__).resolve().parents[1]
    align(Path(sys.argv[1]), repo / 'configs/rodin-304-module-reference.json',
          repo / 'configs/rodin-6.6.77-ksun-susfs.fragment')
