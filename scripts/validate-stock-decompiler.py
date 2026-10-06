#!/usr/bin/env python3
"""Fail closed on incomplete Ghidra run. Passing means output inventory only."""
import argparse
from collections import Counter
import csv
import hashlib
import json
from pathlib import Path


def validate(selected, folder, log):
    expected = json.loads(selected.read_text())
    messages = log.read_text()
    if 'SCRIPT ERROR' in messages or 'pcode error' in messages:
        raise ValueError('Ghidra script/pcode error; exit status alone is insufficient')
    with (folder / 'status.tsv').open(newline='') as stream:
        rows = list(csv.DictReader(stream, delimiter='\t'))
    if Counter(r['symbol'] for r in rows) != Counter(expected):
        raise ValueError('selected/status symbol inventory mismatch')
    for row in rows:
        if row['status'] != 'decompiled_unverified':
            raise ValueError('incomplete or gapped output: ' + row['symbol'])
        filename = ''.join(c if c.isalnum() or c in '_.-' else '_' for c in row['symbol']) + '.pseudo.c'
        text = (folder / filename).read_text()
        if 'halt_baddata' in text or 'Truncating control flow' in text:
            raise ValueError('bad-flow pseudocode: ' + row['symbol'])
    return len(rows)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for key in ('selected', 'folder', 'log'):
        parser.add_argument('--' + key, type=Path, required=True)
    args = parser.parse_args()
    count = validate(args.selected, args.folder, args.log)
    manifest = {str(p.relative_to(args.folder)): hashlib.sha256(p.read_bytes()).hexdigest()
                for p in sorted(args.folder.glob('*.pseudo.c'))}
    (args.folder / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print(f'PASS: {count} inventoried pseudocode outputs; semantic validation still required')
