#!/usr/bin/env python3
"""Verify actual PREL32 exports and relative references in the pinned Image."""
import argparse
from bisect import bisect_right
import hashlib
import io
from importlib.machinery import SourceFileLoader
import json
from pathlib import Path
import struct

m = SourceFileLoader('stock_export_reference', str(Path(__file__).with_name('scan-dmabuf-stock-activation.py'))).load_module()


def relative_sites(data, base, target):
    # A match alone is a candidate, not proof this word is a pointer.
    return [base + offset for offset in range(0, len(data) - 3, 4)
            if base + offset + struct.unpack_from('<i', data, offset)[0] == target]


def export_rows(kernel):
    validated_names = kernel.exports()  # names/CRCs checked against kallsyms
    rows = []
    for suffix in ('', '_gpl'):
        low = kernel.address('__start___ksymtab' + suffix)
        high = kernel.address('__stop___ksymtab' + suffix)
        for site in range(low, high, 12):
            offset = site - kernel.base
            value, name_offset, namespace_offset = struct.unpack_from('<iii', kernel.data, offset)
            name_site = offset + 4 + name_offset
            name = kernel.data[name_site:kernel.data.index(b'\0', name_site)].decode()
            if name not in validated_names:
                raise ValueError('export table identity disagreement')
            address = site + value
            # Stock contains same-name static/global functions (e.g. dev_open).
            # The PREL32 value, not guessed unique-name ownership, selects it.
            if address not in {entry[0] for entry in kernel.symbols[name]}:
                raise ValueError('PREL32 export value disagrees with symbol: ' + name)
            namespace_site = offset + 8 + namespace_offset
            if not 0 <= namespace_site < len(kernel.data):
                raise ValueError('export namespace outside image')
            namespace = kernel.data[namespace_site:kernel.data.index(b'\0', namespace_site)].decode()
            rows.append(dict(name=name, site=hex(site), target=hex(address), namespace=namespace, gpl=bool(suffix)))
    return rows


def frame_context(kernel, site, target):
    from elftools.dwarf.callframe import CallFrameInfo, FDE
    from elftools.dwarf.structs import DWARFStructs
    low, high = kernel.address('__eh_frame_start'), kernel.address('__eh_frame_end')
    if not low <= site < high:
        return None
    payload = kernel.data[low-kernel.base:high-kernel.base]
    position = 0
    while position < len(payload):
        if position + 4 > len(payload):
            raise ValueError('truncated EH record length')
        length = struct.unpack_from('<I', payload, position)[0]
        if length == 0:
            position += 4
            continue
        if length == 0xffffffff or length < 4 or position + 4 + length > len(payload):
            raise ValueError('unsupported/truncated EH record')
        end = position + 4 + length
        if low + position <= site < low + end:
            reader = CallFrameInfo(io.BytesIO(payload), len(payload), low,
                DWARFStructs(little_endian=True, dwarf_format=32, address_size=8), for_eh_frame=True)
            entry = reader._parse_entry_at(position)
            if (not isinstance(entry, FDE) or site != low + position + 8 or
                    entry.header.initial_location != target or
                    entry.cie.augmentation_dict.get('FDE_encoding') != 0x1b):
                raise ValueError('relative candidate is not the expected pcrel/sdata4 FDE start')
            return dict(kind='EH_FRAME_FDE_INITIAL_LOCATION_NOT_CALLER', record_site=hex(low+position),
                        cie_site=hex(low+entry.cie.offset), encoding='DW_EH_PE_pcrel|DW_EH_PE_sdata4',
                        initial_location=hex(entry.header.initial_location),
                        address_range=entry.header.address_range,
                        record_bytes=4+length)
        position = end
    raise ValueError('EH candidate not in a complete record')


def run(args):
    for path, sha in ((args.image, m.IMAGE_SHA), (args.symbols, m.SYMBOL_SHA)):
        if path.is_symlink() or hashlib.sha256(path.read_bytes()).hexdigest() != sha:
            raise ValueError('pinned stock input required')
    if args.output.exists() or args.output.is_symlink():
        raise ValueError('evidence exists')
    kernel = m.evidence.Kernel(args.image, args.symbols)
    target = kernel.address('dmabuf_huge_remap_pfn_range')
    rows = export_rows(kernel)
    addresses = sorted(kernel.names_at)
    references = []
    for site in relative_sites(kernel.data, kernel.base, target):
        owner = addresses[bisect_right(addresses, site) - 1]
        references.append(dict(site=hex(site), inferred_owner=kernel.names_at[owner], owner_offset=site-owner,
                               frame_context=frame_context(kernel, site, target)))
    exports = [r for r in rows if int(r['target'], 16) == target or r['name'] == 'dmabuf_huge_remap_pfn_range']
    report = dict(status='PINNED_STATIC_EXPORT_REFERENCE_EVIDENCE_NOT_RUNTIME_ACTIVATION',
                  image_sha256=m.IMAGE_SHA, symbols_sha256=m.SYMBOL_SHA,
                  target=hex(target), validated_export_count=len(rows), target_exports=exports,
                  ordinary_mapper_exports=[r for r in rows if r['name'] in ('remap_pfn_range', 'dma_buf_mmap')],
                  aligned_prel32_target_candidates=references,
                  limits=['PREL32 candidates may be coincidental integers; no pointer/CFG proof',
                          'does not resolve register-built pointers or runtime lookup',
                          'absence from export tables excludes ordinary module symbol import, not every activation route'])
    with args.output.open('x') as stream:
        stream.write(json.dumps(report, indent=2) + '\n')
    print(f'PASS: {len(rows)} PREL32 exports validated; mapper exports={len(exports)}, relative candidates={len(references)}')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('image', 'symbols', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    run(parser.parse_args())
