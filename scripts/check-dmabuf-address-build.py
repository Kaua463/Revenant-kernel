#!/usr/bin/env python3
"""Check linked DMA fops callback in disposable ARM64 audit vmlinux."""
import argparse
import json
from pathlib import Path
import struct


def registration(data, fops, callback):
    if fops['size'] < 160 or len(data) != fops['size']:
        raise ValueError('incomplete linked fops object')
    if callback['type'] != 'STT_FUNC' or not callback['size'] or not callback['address']:
        raise ValueError('missing linked selector function')
    if struct.unpack_from('<Q',data,152)[0] != callback['address']:
        raise ValueError('linked fops selector pointer mismatch')
    return {'status':'COMPILE_REGISTRATION_ONLY_NOT_RUNTIME', 'offset_bytes':152,
            'fops':fops,'callback':callback}


def run(args):
    from elftools.elf.elffile import ELFFile
    if args.output.exists() or args.output.is_symlink():
        raise ValueError('evidence exists')
    with args.vmlinux.open('rb') as stream:
        elf = ELFFile(stream)
        if elf.header['e_machine'] != 'EM_AARCH64' or not elf.little_endian or elf.elfclass != 64:
            raise ValueError('expected little-endian ELF64 ARM64')
        table = elf.get_section_by_name('.symtab')
        if table is None:
            raise ValueError('symbol table absent')
        found = {}
        for name in ('dma_buf_fops','dma_buf_hugetlb_get_unmapped_area'):
            rows = [s for s in table.iter_symbols() if s.name == name and s['st_shndx'] != 'SHN_UNDEF']
            if len(rows) != 1 or not isinstance(rows[0]['st_shndx'],int):
                raise ValueError('missing/ambiguous file-backed symbol: '+name)
            found[name] = rows[0]
        fops, callback = found.values()
        if fops['st_info']['type'] != 'STT_OBJECT':
            raise ValueError('fops is not object')
        section = elf.get_section(fops['st_shndx'])
        if section['sh_type'] == 'SHT_NOBITS':
            raise ValueError('fops unexpectedly uninitialized')
        offset = fops['st_value']-section['sh_addr']
        if not 0 <= offset <= section['sh_size']-fops['st_size']:
            raise ValueError('fops outside section')
        def describe(s):
            return {'address':s['st_value'],'size':s['st_size'],'type':s['st_info']['type']}
        result = registration(section.data()[offset:offset+fops['st_size']],describe(fops),describe(callback))
    args.output.parent.mkdir(parents=True,exist_ok=True)
    with args.output.open('x') as stream:
        json.dump(result,stream,indent=2)
        stream.write('\n')
    print('PASS: linked DMA fops selector pointer; no runtime route proof')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--vmlinux',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    run(parser.parse_args())
