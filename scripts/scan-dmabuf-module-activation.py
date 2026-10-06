#!/usr/bin/env python3
"""Read-only activation pattern inventory across the pinned 610 ROM module rows."""
import argparse
from bisect import bisect_right
import hashlib
from importlib.machinery import SourceFileLoader
import io
import json
from pathlib import Path
import struct
from elftools.elf.elffile import ELFFile

decoder = SourceFileLoader('dma_module_activation_decoder', str(Path(__file__).with_name('scan-dmabuf-stock-activation.py'))).load_module()
REFERENCE_SHA = 'c89309f2205c70dd87d8b3c3a6c679480582b6e9313573b1f3f894d5bad8146c'
TARGET = 'dmabuf_huge_remap_pfn_range'


def scan(data):
    elf = ELFFile(io.BytesIO(data))
    if elf['e_machine'] != 'EM_AARCH64' or elf['e_type'] != 'ET_REL' or not elf.little_endian:
        raise ValueError('little-endian ARM64 relocatable module required')
    table = elf.get_section_by_name('.symtab')
    if table is None:
        raise ValueError('module symbol table required')
    symbols = list(table.iter_symbols())
    target_symbols = [{'name': s.name, 'section': s['st_shndx'], 'value': s['st_value']}
                      for s in symbols if s.name == TARGET]
    candidates, literals = [], []
    code_bytes = 0
    for index, section in enumerate(elf.iter_sections()):
        # NOBITS is runtime allocation, never file-backed extracted bytes.
        if section['sh_type'] == 'SHT_NOBITS':
            continue
        payload = section.data()
        if TARGET.encode() in payload:
            literals.append(section.name)
        if not section['sh_flags'] & 4:
            continue
        code_bytes += len(payload)
        functions = {}
        for symbol in symbols:
            if symbol['st_shndx'] == index and symbol['st_info']['type'] == 'STT_FUNC' and symbol['st_size']:
                functions.setdefault(symbol['st_value'], []).append((symbol.name, symbol['st_size']))
        starts = sorted(functions)
        for offset in range(0, len(payload) - 3, 4):
            word = struct.unpack_from('<I', payload, offset)[0]
            mask = decoder.orr_mask(word)
            if mask is None or not mask & (1 << 39):
                continue
            position = bisect_right(starts, offset) - 1
            owners = [] if position < 0 else [name for name, size in functions[starts[position]] if offset < starts[position] + size]
            candidates.append({'section': section.name, 'offset': hex(offset),
                               'elf_function_bounds': owners, 'mask': hex(mask),
                               'only_bit39': mask == 1 << 39})
    return {'code_bytes': code_bytes, 'target_symbols': target_symbols,
            'literal_sections': literals, 'orr_masks_containing_bit39': candidates}


def run(args):
    reference_bytes = args.reference.read_bytes()
    if hashlib.sha256(reference_bytes).hexdigest() != REFERENCE_SHA:
        raise ValueError('module reference pin mismatch')
    reference = json.loads(reference_bytes)
    rows = reference['modules']
    if len(rows) != 610 or reference['signed_count'] != 78:
        raise ValueError('incomplete stock inventory')
    if args.output.exists() or args.output.is_symlink():
        raise ValueError('output already exists')
    wanted = {(row['sha256'], Path(row['path']).name) for row in rows}
    by_name = {name for _, name in wanted}
    located = {}
    # Only technical extraction root; digest identity selects 6.6.77, not
    # another release or a basename-only substitution. Never inspect user data.
    for path in sorted(args.root.rglob('*.ko')):
        if path.name not in by_name:
            continue
        if path.is_symlink() or not path.resolve().is_relative_to(args.root.resolve()):
            raise ValueError('module path escapes extraction root')
        key = (hashlib.sha256(path.read_bytes()).hexdigest(), path.name)
        if key in wanted:
            located.setdefault(key, path)
    if set(located) != wanted:
        raise ValueError('pinned module bytes missing: ' + str(sorted(wanted - set(located))))
    unique = {}
    for number, (key, path) in enumerate(sorted(located.items()), 1):
        sha, _ = key
        if sha in unique:
            continue
        data = path.read_bytes()
        if hashlib.sha256(data).hexdigest() != sha:
            raise ValueError('module changed while scanning')
        unique[sha] = scan(data)
        if path.read_bytes() != data:
            raise ValueError('audit modified module')
        if number % 32 == 0:
            print(f'Scanned {number}/{len(located)} pinned identities', flush=True)
    result = {'status': 'STATIC_MODULE_ACTIVATION_CANDIDATES_NOT_RUNTIME_PROOF',
              'reference_sha256': REFERENCE_SHA, 'module_rows': len(rows),
              'unique_bytes': len(unique), 'rows': rows, 'scans_by_sha256': unique,
              'limits': ['instruction patterns not CFG/reachability or VMA store proof',
                         'literal in strtab/BTF is not dynamic lookup proof',
                         'masks built through registers/loads and runtime activation unresolved',
                         'static inventory does not prove module loading order']}
    with args.output.open('x') as stream:
        json.dump(result, stream, indent=2)
        stream.write('\n')
    print(f'PASS: {len(rows)} rows / {len(unique)} unique module bytes scanned read-only; not activation proof')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('root', 'reference', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    run(parser.parse_args())
