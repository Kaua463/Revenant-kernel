#!/usr/bin/env python3
"""Prepare bounded Ghidra seeds and BTF evidence from a hash-checked stock Image."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import struct


def pattern_for_scope(scope):
    patterns = {'all': r'xring_lb|dmabuf_huge|iostat|fastdiscard', 'dmabuf': r'dmabuf_huge'}
    if scope not in patterns:
        raise ValueError('unsupported recovery scope')
    return patterns[scope]


def run(args):
    spec = importlib.util.spec_from_file_location('contracts', Path(__file__).with_name('verify-stock-recovered-contracts.py'))
    contracts = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(contracts)
    if hashlib.sha256(args.image.read_bytes()).hexdigest() != contracts.IMAGE_SHA:
        raise ValueError('stock Image hash mismatch')
    if hashlib.sha256(args.symbols.read_bytes()).hexdigest() != contracts.SYMBOL_SHA:
        raise ValueError('stock kallsyms hash mismatch')
    if args.output.exists():
        raise ValueError('output must not exist')
    spec = importlib.util.spec_from_file_location('compare', Path(__file__).with_name('stock-binary-evidence.py'))
    compare = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(compare)
    kernel = compare.Kernel(args.image, args.symbols)
    scope = getattr(args, 'scope', 'all')
    pattern = pattern_for_scope(scope)
    seeds = {n for n in kernel.symbols if re.search(pattern, n)}
    for name in args.extra_symbol:
        if name not in kernel.symbols:
            raise ValueError('requested extra symbol missing: ' + name)
        seeds.add(name)
    # Include generic local helpers in the contiguous, non-init XRING text region.
    xring = [a for a, k, n in kernel.entries if scope == 'all' and k in 'tT' and n.startswith('xring_lb_')
             and a < kernel.address('_etext')]
    if scope == 'all' and not xring:
        raise ValueError('XRING text functions missing')
    first, last = (min(xring), max(xring)) if xring else (-1, -1)
    seeds.update(n for a, k, n in kernel.entries if first <= a <= last and k in 'tT')
    callees = set()
    for name in seeds:
        rows = kernel.symbols[name]
        data = kernel.span(name)
        if len(rows) != 1 or rows[0][1] not in 'tT' or data is None:
            continue
        address = rows[0][0]
        for offset in range(0, len(data) - 3, 4):
            word = struct.unpack_from('<I', data, offset)[0]
            if word & 0x7c000000 != 0x14000000:
                continue
            immediate = word & 0x03ffffff
            if immediate & 0x02000000:
                immediate -= 0x04000000
            target = address + offset + immediate * 4
            callees.update(kernel.names_at.get(target, []))
    function_types = {}
    for ident, typ in enumerate(kernel.btf.types):
        if typ['kind'] == 12:
            function_types.setdefault(typ['name'], []).append(ident)
    args.output.mkdir(parents=True)
    selected = []
    tsv = []
    # All unique symbols are labels only. Disassemble/create bodies for selected code only.
    for address, kind, n in sorted(kernel.entries):
        rows = kernel.symbols[n]
        end = kernel.next_address.get(address, address + 1)
        backed = 0 <= address - kernel.base < end - kernel.base <= len(kernel.data)
        is_selected = (bool(re.search(pattern, n)) or first <= address <= last or n in args.extra_symbol) and kind in 'tT' and backed
        label = n if len(rows) == 1 else n + '__at_' + format(address, 'x')
        role = 1 if is_selected else (2 if n in callees and kind in 'tT' else 0)
        variants = function_types.get(n, [])
        shapes = {kernel.btf.ref(kernel.btf.types[i]['size']) for i in variants}
        type_id = variants[0] if variants and len(shapes) == 1 else 0
        # Duplicate names remain explicitly address-qualified, never silently discarded.
        tsv.append(f'{address:x}\t{kind}\t{label}\t{role}\t{end:x}\t{type_id}\t{n}')
        if is_selected:
            selected.append(label)
    (args.output / 'seeds.tsv').write_text('\n'.join(tsv) + '\n')
    named = kernel.btf.named_types()
    records = kernel.btf.records()
    # Preserve exact BTF names/prototypes/layouts rather than inventing function signatures.
    interesting = r'erofs.*iostat|lb_(?!env)|file_info|file_interval|file_record|record_(disk|info)|iostat'
    related = {n: v for n, v in records.items() if re.search(interesting, n)}
    if scope == 'dmabuf':
        related = {n: records[n] for n in ('struct vm_area_struct', 'struct mm_struct', 'struct page', 'struct ptdesc',
                                          'struct file', 'struct address_space', 'struct anon_vma', 'struct mmu_gather')}
    else:
        related.update({n: records[n] for n in ('struct bio', 'struct erofs_sb_info', 'struct file_operations')})
    prototypes = {n: v for n, v in named.items() if n.startswith('12:') and n[3:] in seeds}
    (args.output / 'btf-contracts.json').write_text(json.dumps({'records': related, 'functions': prototypes}, indent=2) + '\n')
    # Full raw BTF table enables later import of transitive definitions without guessing.
    (args.output / 'btf-types.json').write_text(json.dumps(kernel.btf.types, indent=2) + '\n')
    (args.output / 'selected.json').write_text(json.dumps(selected, indent=2) + '\n')
    print(f'Prepared {len(selected)} selected code spans; {len(related)} BTF records; {len(prototypes)} prototypes')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for key in ('image', 'symbols', 'output'):
        parser.add_argument('--' + key, type=Path, required=True)
    parser.add_argument('--extra-symbol',action='append',default=[])
    parser.add_argument('--scope',choices=('all','dmabuf'),default='all')
    run(parser.parse_args())
