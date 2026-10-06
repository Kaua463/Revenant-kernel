#!/usr/bin/env python3
"""Exact stock direct-branch candidates; NOT CFG or absence-of-use proof."""
import argparse
from bisect import bisect_right
import hashlib
from importlib.machinery import SourceFileLoader
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
contract = SourceFileLoader('dma_callers_contract', str(HERE/'verify-stock-recovered-contracts.py')).load_module()
binary = SourceFileLoader('dma_callers_binary', str(HERE/'stock-binary-evidence.py')).load_module()
build = SourceFileLoader('dma_callers_targets', str(HERE/'check-dmabuf-build.py')).load_module()


def branch(word, address):
    opcode = word & 0xfc000000
    if opcode not in (0x14000000, 0x94000000):
        return None
    immediate = word & 0x03ffffff
    if immediate & 0x02000000:
        immediate -= 0x04000000
    return ('BL' if opcode == 0x94000000 else 'B', address + immediate*4)


def scan(data, base, intervals, targets, symbols):
    rows = []
    addresses = sorted(symbols)
    last_end = base
    for start, end in intervals:
        if start % 4 or end % 4 or not base <= start < end <= base+len(data) or start < last_end:
            raise ValueError('invalid/non-disjoint text scan interval')
        last_end = end
        for offset in range(start-base, end-base, 4):
            decoded = branch(struct.unpack_from('<I', data, offset)[0], base+offset)
            if decoded is None or decoded[1] not in targets:
                continue
            position = bisect_right(addresses, base+offset)-1
            nearest = addresses[position] if position >= 0 else None
            rows.append({'address':hex(base+offset), 'image_offset':offset,
                         'instruction':decoded[0], 'target':targets[decoded[1]],
                         'nearest_text_symbols':symbols[nearest] if nearest is not None else [],
                         'nearest_symbol_offset':base+offset-nearest if nearest is not None else None})
    return rows


def run(args):
    if args.output.exists() or args.output.is_symlink():
        raise ValueError('evidence output already exists')
    image, symbols = args.image.read_bytes(), args.symbols.read_bytes()
    if (hashlib.sha256(image).hexdigest()!=contract.IMAGE_SHA or
        hashlib.sha256(symbols).hexdigest()!=contract.SYMBOL_SHA):
        raise ValueError('stock identity mismatch')
    kernel = binary.Kernel(args.image, args.symbols)
    if kernel.data != image:
        raise ValueError('Image changed during inspection')
    targets = {kernel.address(name):name for name in build.FUNCTIONS}
    text_symbols = {}
    for address, kind, name in kernel.entries:
        if kind in ('t', 'T'):
            text_symbols.setdefault(address, []).append(name)
    intervals = [(kernel.address('_stext'),kernel.address('_etext')),
                 (kernel.address('_sinittext'),kernel.address('_einittext'))]
    rows = scan(image,kernel.base,intervals,targets,text_symbols)
    report = {'status':'EXACT_DIRECT_BRANCH_CANDIDATES_NOT_FULL_CALL_GRAPH',
              'image_sha256':contract.IMAGE_SHA, 'symbols_sha256':contract.SYMBOL_SHA,
              'intervals':[{'start':hex(a),'end':hex(b),'bytes':b-a} for a,b in intervals],
              'targets':{name:{'address':hex(address),
                               'direct_branch_count':sum(row['target']==name for row in rows)}
                         for address,name in targets.items()},
              'candidates':rows,
              'limits':['nearest symbol is context, not a proved function boundary',
                        'aligned executable ranges may contain data/padding/CFI',
                        'indirect calls, symbol lookup and module relocations not covered',
                        'zero direct branches never proves unused or safe to remove']}
    if args.image.read_bytes()!=image or args.symbols.read_bytes()!=symbols:
        raise ValueError('stock inputs changed during inspection')
    args.output.parent.mkdir(parents=True,exist_ok=True)
    with args.output.open('x') as stream:
        json.dump(report,stream,indent=2);stream.write('\n')
    print(f'{len(rows)} pinned direct-branch candidates saved; NOT full activation proof')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('image','symbols','output'):
        parser.add_argument('--'+name,type=Path,required=True)
    run(parser.parse_args())
