#!/usr/bin/env python3
"""Compose the pinned root config with DMA; no hidden last-setting-wins edits."""
import argparse
import hashlib
from pathlib import Path
import re

ROOT_SHA = 'ee7329e25bb836ed8543a3c75d99e5fff3ce72a574fdaa11af3e5d8e803e260d'
DMA_SHA = '44ad00eb3209e4e5f66b3863647ae845de016ca353666767c642626445c511f3'


def settings(text):
    values = {}
    for line in text.splitlines():
        enabled = re.fullmatch(r'(CONFIG_[A-Z0-9_]+)=(.+)', line)
        disabled = re.fullmatch(r'# (CONFIG_[A-Z0-9_]+) is not set', line)
        if not enabled and not disabled:
            if line.startswith('CONFIG_'):
                raise ValueError('malformed config setting')
            continue
        name, value = enabled.groups() if enabled else (disabled.group(1), 'n')
        if name in values:
            raise ValueError('duplicate config setting: ' + name)
        values[name] = value
    return values


def combine(root, dma):
    root_values, dma_values = settings(root), settings(dma)
    if set(root_values) & set(dma_values):
        raise ValueError('root/DMA fragment overlap')
    if dma_values != {'CONFIG_TRANSPARENT_HUGEPAGE': 'y', 'CONFIG_XIAOMI_DMABUF_HUGETLB': 'y'}:
        raise ValueError('unexpected DMA config delta')
    return root.rstrip('\n') + '\n\n' + dma


def run(args):
    root, dma = args.root.read_bytes(), args.dma.read_bytes()
    if hashlib.sha256(root).hexdigest() != ROOT_SHA or hashlib.sha256(dma).hexdigest() != DMA_SHA:
        raise ValueError('config fragment pin drift')
    text = combine(root.decode(), dma.decode())
    with args.output.open('x') as output:
        output.write(text)
    print('PASS: pinned root settings unchanged; only THP and DMA enabled; config SHA256=' + hashlib.sha256(text.encode()).hexdigest())


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('root', 'dma', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    run(parser.parse_args())
