#!/usr/bin/env python3
"""Fetch explicitly named public ACK source at the same immutable stock baseline."""
import argparse
import importlib.util
from pathlib import Path, PurePosixPath
import re


def validate_path(value):
    # Explicit integration/lifetime inputs for the pinned DMA MM audit.
    if value in ('mm/Kconfig','mm/Makefile','kernel/fork.c','drivers/dma-buf/dma-buf.c'):
        return value
    path=PurePosixPath(value)
    if (path.is_absolute() or '..' in path.parts or path.as_posix()!=value or
        not re.fullmatch(r'(mm|include|arch|fs)/[A-Za-z0-9_./-]+\.(c|h)',value)):
        raise ValueError('explicit kernel C/header path required')
    return value


def run(args):
    files=[validate_path(value) for value in args.file]
    if len(files)!=len(set(files)):raise ValueError('duplicate source path')
    spec=importlib.util.spec_from_file_location('source',Path(__file__).with_name('fetch-stock-erofs-reference.py'))
    source=importlib.util.module_from_spec(spec);spec.loader.exec_module(source)
    source.FILES=files;source.run(args.output)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--file',action='append',required=True)
    run(parser.parse_args())
