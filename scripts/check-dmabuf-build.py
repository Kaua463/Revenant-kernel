#!/usr/bin/env python3
"""Audit DMA config and ELF provider presence; not hardware/functionality proof."""
import argparse
import hashlib
import json
from pathlib import Path

FUNCTIONS=('__pmd_dmabuf_huge_lock','zap_dmabuf_huge_pmd','__split_dmabuf_huge_pmd',
           'zap_split_dmabuf_huge_pmd','split_dmabuf_huge_pmd_address','vma_adjust_dmabuf_huge',
           '__split_dmabuf_huge_range','split_dmabuf_huge_range','move_dmabuf_huge_pmd',
           'dmabuf_huge_remap_pfn_range')
COUNTERS=tuple('dmabuf_hugetlb_'+n for n in ('pmd_map','contpte_map','pmd_zap','pmd_split'))


def file_digest(path):
    h=hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda:stream.read(1024*1024),b''):h.update(chunk)
    return h.hexdigest()


def select_equal(paths):
    if not paths:raise ValueError('build input absent')
    sha=file_digest(paths[0])
    if any(file_digest(path)!=sha for path in paths[1:]):raise ValueError('conflicting build input candidates')
    return paths[0]


def validate(cfg,table,enabled):
    for name,value in {'CONFIG_ARM64_4K_PAGES':'y','CONFIG_ARM64_VA_BITS_39':'y',
                       'CONFIG_PGTABLE_LEVELS':'3','CONFIG_TRANSPARENT_HUGEPAGE':'y',
                       'CONFIG_HAVE_ARCH_HUGE_VMAP':'y','CONFIG_SMP':'y',
                       'CONFIG_XIAOMI_DMABUF_HUGETLB':enabled}.items():
        if cfg.get(name)!=value:raise ValueError('DMA build config mismatch: '+name)
    if int(cfg['CONFIG_NR_CPUS'])<int(cfg['CONFIG_SPLIT_PTLOCK_CPUS']):raise ValueError('split ptlocks disabled')
    providers={}
    for name in FUNCTIONS+COUNTERS:
        rows=table.get(name,[])
        if enabled=='n':
            if rows:raise ValueError('DMA present in disabled build: '+name)
        else:
            if len(rows)!=1 or not rows[0]['address'] or not rows[0]['size']:raise ValueError('DMA provider missing/ambiguous: '+name)
            if rows[0]['type']!=('STT_FUNC' if name in FUNCTIONS else 'STT_OBJECT'):raise ValueError('DMA provider type mismatch: '+name)
            if name in COUNTERS and rows[0]['size']!=8:raise ValueError('DMA counter size mismatch')
            providers[name]=rows[0]
    return providers


def run(args):
    from elftools.elf.elffile import ELFFile
    vmlinux=select_equal(args.vmlinux);config=select_equal(args.config)
    cfg={}
    for line in config.read_text().splitlines():
        if line.startswith('CONFIG_') and '=' in line:
            key,value=line.split('=',1);cfg[key]=value
        elif line.startswith('# CONFIG_') and line.endswith(' is not set'):cfg[line[2:-11]]='n'
    table={}
    with vmlinux.open('rb') as stream:
        elf=ELFFile(stream)
        if elf['e_machine']!='EM_AARCH64' or elf.elfclass!=64:raise ValueError('expected ARM64 ELF')
        symbols=elf.get_section_by_name('.symtab')
        if symbols is None:raise ValueError('ELF symbol table missing')
        for symbol in symbols.iter_symbols():
            if symbol.name in FUNCTIONS+COUNTERS:
                table.setdefault(symbol.name,[]).append({'type':symbol['st_info']['type'],'address':symbol['st_value'],'size':symbol['st_size']})
    providers=validate(cfg,table,args.enabled)
    report={'status':'OFFLINE_BUILD_SHAPE_ONLY','enabled':args.enabled,'vmlinux_sha256':file_digest(vmlinux),
            'config_sha256':file_digest(config),'providers':providers,
            'pending':['module/KMI closure','producer alignment/ownership/unwind','MMU/SMP/lifetime/hardware']}
    args.output.write_text(json.dumps(report,indent=2)+'\n')
    print(f'PASS: DMA {args.enabled}, {len(providers)} ELF providers; not runtime/installation approval')


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('vmlinux','config'):p.add_argument('--'+name,type=Path,nargs='+',required=True)
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--enabled',choices=('y','n'),required=True);run(p.parse_args())
