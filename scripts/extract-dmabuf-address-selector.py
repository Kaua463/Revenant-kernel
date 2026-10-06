#!/usr/bin/env python3
"""Read-only pinned DMA fops registration + bounded selector instruction evidence.

Registration is proved by BTF field offsets and raw Image pointers. Neither
registration nor disassembly alone proves full mapping/lifetime semantics.
"""
import argparse
import hashlib
from importlib.machinery import SourceFileLoader
import json
from pathlib import Path
import struct

scanner = SourceFileLoader('dma_selector_scan', str(Path(__file__).with_name('scan-dmabuf-stock-activation.py'))).load_module()
FIELDS = {
    'mmap': (704, '*fn(*4:file,*4:vm_area_struct)->1:int', 'dma_buf_mmap_internal'),
    'release': (960, '*fn(*4:inode,*4:file)->1:int', 'dma_buf_file_release'),
    'get_unmapped_area': (1216, '*fn(*4:file,1:unsigned long,1:unsigned long,1:unsigned long,1:unsigned long)->1:unsigned long',
                          'dma_buf_hugetlb_get_unmapped_area'),
}
CORE_SHA = '81c6e69759857e3ba198f2b45b5b5634721119db0e181ed0fd6454f3cdc8fa1c'
PREFIX_SIZE = 672  # Exact pinned entry through terminal __stack_chk_fail BL.


def field_offsets(records):
    if not records:
        raise ValueError('file_operations BTF absent')
    for record in records:
        if record['size_bytes'] != 264:
            raise ValueError('file_operations size drift')
        for name, (offset, signature, _) in FIELDS.items():
            fields = [m for m in record['members'] if m['name'] == name]
            if len(fields) != 1 or (fields[0]['offset_bits'], fields[0]['type'], fields[0]['bitfield_bits']) != (offset, signature, 0):
                raise ValueError('file_operations field drift: ' + name)
    return {name: definition[0] // 8 for name, definition in FIELDS.items()}


def pointer_at(data, base, table, offset, expected):
    position = table + offset - base
    if not 0 <= position <= len(data) - 8:
        raise ValueError('fops field outside file-backed Image')
    value = struct.unpack_from('<Q', data, position)[0]
    if value != expected:
        raise ValueError('fops callback pointer mismatch')
    return {'field_address': hex(table + offset), 'pointer': hex(value), 'offset_bytes': offset}


def run(args):
    if args.output.exists() or args.output.is_symlink():
        raise ValueError('output exists')
    for path, expected in ((args.image, scanner.IMAGE_SHA), (args.symbols, scanner.SYMBOL_SHA),
                           (args.core, CORE_SHA)):
        if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise ValueError('input pin mismatch: ' + str(path))
    kernel = scanner.evidence.Kernel(args.image, args.symbols)
    layouts = [kernel.btf.record(i) for i, t in enumerate(kernel.btf.types)
               if t['kind'] == 4 and t['name'] == 'file_operations']
    offsets = field_offsets(layouts)
    fops = kernel.address('dma_buf_fops')
    registration = {name: dict(pointer_at(kernel.data, kernel.base, fops, offset,
                                          kernel.address(FIELDS[name][2])), symbol=FIELDS[name][2])
                    for name, offset in offsets.items()}
    start = kernel.address('dma_buf_hugetlb_get_unmapped_area')
    span = kernel.span('dma_buf_hugetlb_get_unmapped_area')
    if span is None or len(span) < PREFIX_SIZE:
        raise ValueError('selector file-backed extent insufficient')
    from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
    decoded = list(Cs(CS_ARCH_ARM64, CS_MODE_ARM).disasm(span[:PREFIX_SIZE], start))
    if len(decoded) != PREFIX_SIZE // 4 or any(i.size != 4 for i in decoded):
        raise ValueError('incomplete instruction decode')
    calls = []
    for instruction in decoded:
        if instruction.mnemonic == 'bl':
            target = scanner.branch(int.from_bytes(instruction.bytes, 'little'), instruction.address)
            calls.append({'site': hex(instruction.address), 'destination': hex(target),
                          'symbols': kernel.names_at.get(target, [])})
    if decoded[-1].mnemonic != 'bl' or calls[-1]['symbols'] != ['__stack_chk_fail']:
        raise ValueError('pinned prefix terminal context drift')
    core = args.core.read_text()
    anchor = 'static const struct file_operations dma_buf_fops = {'
    if core.count(anchor) != 1:
        raise ValueError('ACK fops anchor drift')
    block = core.split(anchor, 1)[1].split('};', 1)[0]
    if 'get_unmapped_area' in block:
        raise ValueError('ACK reference unexpectedly registers address selector')
    report = {
        'status': 'REGISTRATION_PROVED_SELECTOR_SEMANTICS_PENDING',
        'image_sha256': scanner.IMAGE_SHA, 'symbols_sha256': scanner.SYMBOL_SHA,
        'ack_core_sha256': CORE_SHA, 'fops_address': hex(fops), 'btf_variants': len(layouts),
        'registration': registration, 'ack_has_address_selector': False,
        'selector_address': hex(start), 'inferred_symbol_span_bytes': len(span),
        'decoded_prefix_bytes': PREFIX_SIZE, 'prefix_sha256': hashlib.sha256(span[:PREFIX_SIZE]).hexdigest(),
        'calls': calls,
        'instructions': [{'site': hex(i.address), 'bytes': bytes(i.bytes).hex(),
                          'mnemonic': i.mnemonic, 'operands': i.op_str} for i in decoded],
        'limits': ['prefix boundary pinned from noreturn context, not ELF function size',
                   'CPU alternatives remain unapplied', 'no address-selection semantic or MMU proof',
                   'no shipping overlay modification or device access'],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open('x') as stream:
        json.dump(report, stream, indent=2)
        stream.write('\n')
    print(json.dumps({k: report[k] for k in ('status', 'registration', 'calls')}))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('image', 'symbols', 'core', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    run(parser.parse_args())
