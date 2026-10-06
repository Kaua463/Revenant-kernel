#!/usr/bin/env python3
"""Stock ARM64 wrapper routing vs recovered C; MM/split helpers are trace models."""
import argparse
import ctypes
import hashlib
import importlib.util
from pathlib import Path
import random
import struct
import subprocess
import tempfile


FIXTURE=r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
typedef uint64_t pmd_t;
struct mm_struct; struct folio;
struct vm_area_struct { unsigned long vm_start, vm_end; struct mm_struct *vm_mm; };
#define HPAGE_PMD_SIZE (1UL<<21)
#define HPAGE_PMD_MASK (~(HPAGE_PMD_SIZE-1))
static struct vm_area_struct vma, next;
static uint64_t rows[32][6];static unsigned nr,missing_mask,find_calls;
static uint64_t normalized_vma(const void *p) { return p==&vma ? 0x1000000 : p==&next ? 0x1001000 : 0; }
static void record(uint64_t op,uint64_t a,uint64_t b,uint64_t c,uint64_t d,uint64_t e) {
 assert(nr<32);uint64_t row[]={op,a,b,c,d,e};memcpy(rows[nr++],row,sizeof(row));
}
static pmd_t *mm_find_pmd(struct mm_struct *mm,unsigned long addr) {
 record(1,(uintptr_t)mm,addr,0,0,0);
 return missing_mask & (1U<<find_calls++) ? NULL : (void *)0x1002000;
}
static void __split_dmabuf_huge_pmd(struct vm_area_struct *v,pmd_t *p,unsigned long a,bool f,struct folio *folio) {
 record(2,normalized_vma(v),(uintptr_t)p,a,f,(uintptr_t)folio);
}
static struct vm_area_struct *find_vma(struct mm_struct *mm,unsigned long addr) {
 record(3,(uintptr_t)mm,addr,0,0,0);return &next;
}
'''


WRAPPER=r'''
unsigned host_test(unsigned operation,const uint64_t *input,uint64_t *out) {
 vma=(struct vm_area_struct){input[0],input[1],(void *)0x1234};
 next=(struct vm_area_struct){input[2],input[3],(void *)0x5678};
 nr=0;find_calls=0;missing_mask=input[7];
 if(operation==0) vma_adjust_dmabuf_huge(input[8]?NULL:&vma,input[4],input[5],(long)input[6]);
 else if(operation==1) split_dmabuf_huge_pmd_address(&vma,input[4],input[9],(void *)input[10]);
 else zap_split_dmabuf_huge_pmd(&vma,(void *)0x1002000,input[4],input[9],(void *)input[10]);
 memcpy(out,rows,nr*6*sizeof(uint64_t));return nr;
}
'''


def load(name):
    spec=importlib.util.spec_from_file_location(name,Path(__file__).with_name(name));module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


def btf_fields(btf, ident, base=0):
    """Flatten anonymous struct/union members only, preserving absolute bit offsets."""
    result={};typ=btf.types[ident]
    assert typ['kind'] in (4,5)
    def add(name,offset):
        if name in result and result[name]!=offset:raise ValueError('ambiguous anonymous BTF member: '+name)
        result[name]=offset
    for index in range(0,len(typ['raw']),3):
        name,child,offset=typ['raw'][index:index+3]
        offset=(offset&0xffffff) if typ['flag'] else offset
        name=btf.string(name)
        if name:add(name,(base+offset)//8)
        elif btf.types[child]['kind'] in (4,5):
            for name,offset in btf_fields(btf,child,base+offset).items():add(name,offset)
    return result


def run(args):
    from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE
    from unicorn.arm64_const import UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X2,UC_ARM64_REG_X3,UC_ARM64_REG_X4,UC_ARM64_REG_X30,UC_ARM64_REG_SP,UC_ARM64_REG_PC
    contracts=load('verify-stock-recovered-contracts.py');image=args.image.read_bytes()
    assert hashlib.sha256(image).hexdigest()==contracts.IMAGE_SHA
    assert hashlib.sha256(args.symbols.read_bytes()).hexdigest()==contracts.SYMBOL_SHA
    kernel=load('stock-binary-evidence.py').Kernel(args.image,args.symbols)
    ident=next(i for i,t in enumerate(kernel.btf.types) if t['kind']==4 and t['name']=='vm_area_struct')
    fields=btf_fields(kernel.btf,ident)
    assert [fields[n] for n in ('vm_start','vm_end','vm_mm')]==[0,8,16]
    source=FIXTURE+(Path(__file__).parents[1]/'tools/stock-recovery/dmabuf_huge_wrappers.recovered.c').read_text()+WRAPPER
    with tempfile.TemporaryDirectory(prefix='dmabuf-wrappers-') as folder:
        lib=Path(folder)/'wrappers.dylib'
        subprocess.run(['clang','-x','c','-std=c11','-Wall','-Wextra','-Werror','-dynamiclib','-o',str(lib),'-'],input=source,text=True,check=True)
        host=ctypes.CDLL(str(lib));host.host_test.argtypes=[ctypes.c_uint,ctypes.c_void_p,ctypes.c_void_p]
        uc=Uc(UC_ARCH_ARM64,UC_MODE_ARM);uc.mem_map(kernel.base,(len(image)+4095)&~4095);uc.mem_write(kernel.base,image)
        ram=0x1000000;uc.mem_map(ram,0x20000);vma,next_vma,pmd,stack,stop=[ram+x for x in (0,0x1000,0x2000,0xf000,0x10000)]
        trace=[];state={}
        def hook(emu,address,size,user):
            if address not in helpers:return
            name=helpers[address];values=[emu.reg_read(r) for r in (UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X2,UC_ARM64_REG_X3,UC_ARM64_REG_X4)]
            if name=='mm_find_pmd':
                trace.append((1,values[0],values[1],0,0,0));result=0 if state['missing']&(1<<state['find']) else pmd;state['find']+=1
            elif name=='find_vma':trace.append((3,values[0],values[1],0,0,0));result=next_vma
            else:trace.append((2,*values));result=0
            emu.reg_write(UC_ARM64_REG_X0,result);emu.reg_write(UC_ARM64_REG_PC,emu.reg_read(UC_ARM64_REG_X30))
        helpers={kernel.address(n):n for n in ('mm_find_pmd','find_vma','__split_dmabuf_huge_pmd')};uc.hook_add(UC_HOOK_CODE,hook)
        rng=random.Random(0x304d);count=0
        boundaries=(0,1,(1<<21)-1,1<<21,(1<<21)+1,2<<21,(1<<64)-1)
        for case in range(args.cases):
            start=rng.randrange(0,8)<<21;end=start+(rng.randrange(1,8)<<21)
            next_start=end;next_end=end+(4<<21)
            a=boundaries[case%len(boundaries)] if case<len(boundaries)*8 else rng.randrange(0,20<<21)
            b=boundaries[(case+1)%len(boundaries)] if case<len(boundaries)*8 else rng.randrange(0,20<<21)
            adj=(-1,0,1,1<<21,(1<<21)-1,4<<21)[case%6]
            null_vma=case%13==0
            if null_vma:adj=0
            values=(start,end,next_start,next_end,a,b,adj&((1<<64)-1),case%8,null_vma,case&1,0 if case%3==0 else 0x9876)
            native_input=(ctypes.c_uint64*11)(*values)
            for operation,name in enumerate(('vma_adjust_dmabuf_huge','split_dmabuf_huge_pmd_address','zap_split_dmabuf_huge_pmd')):
                native_rows=(ctypes.c_uint64*(32*6))();n=host.host_test(operation,native_input,native_rows)
                expected=[tuple(native_rows[i*6:(i+1)*6]) for i in range(n)]
                uc.mem_write(vma,struct.pack('<QQQ',start,end,0x1234));uc.mem_write(next_vma,struct.pack('<QQQ',next_start,next_end,0x5678))
                trace.clear();state.update(find=0,missing=case%8)
                arguments=([0 if null_vma else vma,a,b,values[6]] if operation==0 else
                           [vma,a,values[9],values[10]] if operation==1 else [vma,pmd,a,values[9],values[10]])
                for r,value in zip((UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X2,UC_ARM64_REG_X3,UC_ARM64_REG_X4),arguments):uc.reg_write(r,value)
                uc.reg_write(UC_ARM64_REG_X30,stop);uc.reg_write(UC_ARM64_REG_SP,stack)
                uc.emu_start(kernel.address(name),stop,count=50000)
                assert uc.reg_read(UC_ARM64_REG_PC)==stop,'instruction bound exceeded'
                assert trace==expected,(case,name,trace,expected)
                assert bytes(uc.mem_read(vma,24))==struct.pack('<QQQ',start,end,0x1234)
                assert bytes(uc.mem_read(next_vma,24))==struct.pack('<QQQ',next_start,next_end,0x5678)
                count+=1
        print(f'PASS: {count} stock ARM64 wrapper routes vs recovered C; argument/order/boundary/ignored-freeze checks')
        print('Split/MM helpers are models; no claim about page-table writes, TLB, locks, complete feature or hardware.')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--image',type=Path,required=True);parser.add_argument('--symbols',type=Path,required=True);parser.add_argument('--cases',type=int,default=1000)
    run(parser.parse_args())
