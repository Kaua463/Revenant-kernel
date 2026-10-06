#!/usr/bin/env python3
"""Pinned ELF relocation routes for stock heap/Mali mmap; no reachability claim."""
import argparse
import hashlib
import io
import json
from pathlib import Path
import struct
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection

REFERENCE_SHA = 'c89309f2205c70dd87d8b3c3a6c679480582b6e9313573b1f3f894d5bad8146c'
SELECTED = {'mali_kbase_mt6899_r49.ko', 'system_heap.ko', 'mtk_sec_heap.ko'}
ENDPOINTS = {'dma_buf_mmap', 'remap_pfn_range', 'remap_vmalloc_range',
             'dmabuf_huge_remap_pfn_range'}


def inspect(data):
    elf = ELFFile(io.BytesIO(data))
    if elf['e_machine'] != 'EM_AARCH64' or elf['e_type'] != 'ET_REL' or not elf.little_endian:
        raise ValueError('expected little-endian ARM64 ET_REL')
    table = elf.get_section_by_name('.symtab')
    if table is None:
        raise ValueError('symbol table required')
    symbols = list(table.iter_symbols())
    functions = [s for s in symbols if s['st_info']['type']=='STT_FUNC' and s['st_size']]
    objects = [s for s in symbols if s['st_info']['type']=='STT_OBJECT' and s['st_size']]
    routes, registrations = [], []
    for relocations in elf.iter_sections():
        if not isinstance(relocations, RelocationSection):
            continue
        if relocations['sh_link'] != elf.get_section_index('.symtab'):
            raise ValueError('unexpected relocation symbol table')
        index = relocations['sh_info']
        section = elf.get_section(index)
        if section['sh_type']=='SHT_NOBITS':
            continue
        payload = section.data()
        for reloc in relocations.iter_relocations():
            offset, kind = reloc['r_offset'], reloc['r_info_type']
            target = symbols[reloc['r_info_sym']]
            owners = [s for s in functions if s['st_shndx']==index and
                      s['st_value'] <= offset < s['st_value']+s['st_size']]
            if kind in (282, 283) and section['sh_flags'] & 4:
                if offset%4 or offset+4>len(payload):
                    raise ValueError('invalid branch relocation offset')
                word = struct.unpack_from('<I', payload, offset)[0]
                if word & 0xfc000000 != (0x94000000 if kind==283 else 0x14000000):
                    raise ValueError('branch relocation opcode mismatch')
                for owner in owners:
                    if 'mmap' in owner.name or target.name in ENDPOINTS:
                        routes.append({'caller':owner.name, 'caller_offset':offset-owner['st_value'],
                                       'section':section.name, 'relocation_offset':offset,
                                       'kind':'CALL26' if kind==283 else 'JUMP26',
                                       'target':target.name, 'target_section':target['st_shndx'],
                                       'addend':reloc['r_addend']})
            # Data registration: handle both named function and section+addend.
            if kind==257 and not section['sh_flags'] & 4:
                address = target['st_value']+reloc['r_addend']
                callbacks = [s for s in functions if 'mmap' in s.name and
                             s['st_shndx']==target['st_shndx'] and s['st_value']==address]
                if callbacks:
                    containers = [s for s in objects if s['st_shndx']==index and
                                  s['st_value']<=offset<s['st_value']+s['st_size']]
                    registrations.append({'section':section.name,'offset':offset,
                                          'callbacks':[s.name for s in callbacks],
                                          'containers':[{'name':s.name, 'field_offset':offset-s['st_value'],
                                                         'size':s['st_size']} for s in containers]})
    return {'mmap_functions':[{'name':s.name,'size':s['st_size']} for s in functions if 'mmap' in s.name],
            'branch_routes':routes, 'data_callback_registrations':registrations,
            'special_mapper_symbols':[s.name for s in symbols if s.name=='dmabuf_huge_remap_pfn_range']}


def run(args):
    if args.output.exists() or args.output.is_symlink():
        raise ValueError('output must not exist')
    reference_data = args.reference.read_bytes()
    if hashlib.sha256(reference_data).hexdigest()!=REFERENCE_SHA:
        raise ValueError('reference pin mismatch')
    reference = json.loads(reference_data)
    if len(reference['modules'])!=610 or reference['signed_count']!=78:
        raise ValueError('incomplete module reference')
    wanted = {(Path(r['path']).name,r['sha256']) for r in reference['modules']
              if Path(r['path']).name in SELECTED}
    if {name for name,sha in wanted}!=SELECTED or len(wanted)!=3:
        raise ValueError('unexpected selected stock identities')
    found = {}
    for path in sorted(args.root.rglob('*.ko')):
        if path.name not in SELECTED:
            continue
        if path.is_symlink() or not path.resolve().is_relative_to(args.root.resolve()):
            raise ValueError('path escapes extraction root')
        data = path.read_bytes()
        key = (path.name, hashlib.sha256(data).hexdigest())
        if key not in wanted:
            continue # Other extracted ROM versions are not substitutes.
        record = inspect(data)
        if path.read_bytes()!=data:
            raise ValueError('module changed during inspection')
        found[key] = record
    if set(found)!=wanted:
        raise ValueError('pinned selected module missing')
    report = {'status':'EXACT_ELF_ROUTES_NOT_FULL_ACTIVATION_PROOF',
              'reference_sha256':REFERENCE_SHA,
              'modules':{name:{'sha256':sha, **record} for (name,sha),record in sorted(found.items())},
              'limits':['direct ELF relocation route, not branch reachability or actual module load',
                        'callback data relocation does not prove execution',
                        'indirect calls, alternate exporters and runtime symbol lookup unresolved',
                        'GPU MMU mapping and CPU VMA mapping must not be conflated']}
    with args.output.open('x') as stream:
        json.dump(report,stream,indent=2);stream.write('\n')
    print('PASS: three exact-stock heap/Mali ELF route inventories; modules unchanged')


if __name__=='__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('root','reference','output'):
        parser.add_argument('--'+name,type=Path,required=True)
    run(parser.parse_args())
