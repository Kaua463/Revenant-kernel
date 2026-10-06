#!/usr/bin/env python3
"""Stock copy_page_range fork hook with empty source page tables; not PTE-copy proof."""
import argparse
import ctypes
import hashlib
from pathlib import Path
import struct
import subprocess
import tempfile
from importlib.machinery import SourceFileLoader


def load(name):return SourceFileLoader(name,str(Path(__file__).with_name(name))).load_module()


FIXTURE=r'''
#include <stdint.h>
#include <string.h>
struct vm_area_struct {uint64_t vm_flags;unsigned seq,mm_seq,index;};
static uint64_t rows[8][2];static unsigned nr;
static void split_dmabuf_huge_range(struct vm_area_struct *s){rows[nr][0]=1;rows[nr++][1]=s->index?0x1000000:0x1002000;}
static void vm_flags_clear(struct vm_area_struct *s,uint64_t f){if(s->seq!=s->mm_seq){rows[nr][0]=2;rows[nr++][1]=s->index?0x1006000:0x1007000;s->seq=s->mm_seq;rows[nr][0]=3;rows[nr++][1]=s->index?0x1006000:0x1007000;}s->vm_flags&=~f;}
'''
WRAPPER=r'''
unsigned host_fork(const uint64_t *in,uint64_t *out,uint64_t *trace_out){
 struct vm_area_struct src={in[0],in[2],7,1},dst={in[1],in[3],7,0};nr=0;
 dmabuf_huge_fork_prepare(&dst,&src);out[0]=src.vm_flags;out[1]=dst.vm_flags;out[2]=src.seq;out[3]=dst.seq;
 memcpy(trace_out,rows,nr*2*sizeof(uint64_t));return nr;}
'''


def run(args):
    from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE
    from unicorn.arm64_const import UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X30,UC_ARM64_REG_SP,UC_ARM64_REG_SP_EL0,UC_ARM64_REG_PC
    image=args.image.read_bytes();contract=load('verify-stock-recovered-contracts.py')
    assert hashlib.sha256(image).hexdigest()==contract.IMAGE_SHA and hashlib.sha256(args.symbols.read_bytes()).hexdigest()==contract.SYMBOL_SHA
    kernel=load('stock-binary-evidence.py').Kernel(args.image,args.symbols)
    load('test-dmabuf-stock-remap-pmd.py').verify_btf(kernel)
    btf=kernel.btf;func=next(t for t in btf.types if t['kind']==12 and t['name']=='copy_page_range')
    proto=btf.types[func['size']];assert len(proto['raw'])==4 and btf.types[proto['size']]['name']=='int'
    for index in (1,3):
        pointer=btf.types[proto['raw'][index]]
        assert pointer['kind']==2 and btf.types[pointer['size']]['name']=='vm_area_struct'
    code=FIXTURE+(Path(__file__).parents[1]/'tools/stock-recovery/dmabuf_huge_hooks.recovered.c').read_text()+WRAPPER
    with tempfile.TemporaryDirectory(prefix='dmabuf-fork-') as tmp:
        lib=Path(tmp)/'fork.dylib';subprocess.run(['clang','-x','c','-std=c11','-Wall','-Wextra','-Werror','-dynamiclib','-o',str(lib),'-'],input=code,text=True,check=True)
        host=ctypes.CDLL(str(lib));host.host_fork.argtypes=[ctypes.c_void_p]*3;host.host_fork.restype=ctypes.c_uint
        uc=Uc(UC_ARCH_ARM64,UC_MODE_ARM);uc.mem_map(kernel.base,(len(image)+4095)&~4095);uc.mem_write(kernel.base,image)
        ram=0x1000000;uc.mem_map(ram,0x20000);src=ram;srcmm=ram+0x1000;dst=ram+0x2000;dstmm=ram+0x3000;task=ram+0x8000;stack=ram+0xf000;stop=ram+0x10000
        source_pgd=ram+0x11000;dest_pgd=ram+0x12000
        funcs={kernel.address('split_dmabuf_huge_range'):1,kernel.address('down_write'):2,kernel.address('up_write'):3};trace=[]
        def hook(emu,address,size,user):
            if address in funcs:
                trace.append((funcs[address],emu.reg_read(UC_ARM64_REG_X0)))
                emu.reg_write(UC_ARM64_REG_X0,0);emu.reg_write(UC_ARM64_REG_PC,emu.reg_read(UC_ARM64_REG_X30))
        uc.hook_add(UC_HOOK_CODE,hook)
        for case in range(64):
            source_flags=0x400|((case&1)<<39)|((case&2)<<11)
            dest_flags=0x400|(((case>>1)&1)<<39)|((case&4)<<10)
            values=(source_flags,dest_flags,case%8,(case//8)%8);inputs=(ctypes.c_uint64*4)(*values);out=(ctypes.c_uint64*4)();rows=(ctypes.c_uint64*16)()
            n=host.host_fork(inputs,out,rows);expected=[tuple(rows[i*2:(i+1)*2]) for i in range(n)]
            for v,m,flags,seq,sem,pgd in ((src,srcmm,source_flags,values[2],ram+0x6000,source_pgd),(dst,dstmm,dest_flags,values[3],ram+0x7000,dest_pgd)):
                uc.mem_write(v,bytes(208));uc.mem_write(m,bytes(1600));uc.mem_write(pgd,bytes(4096))
                uc.mem_write(v,struct.pack('<5Q',0x200000,0x400000,m,0,flags));uc.mem_write(v+44,struct.pack('<I',seq));uc.mem_write(v+48,struct.pack('<Q',sem))
                uc.mem_write(m+112,struct.pack('<Q',pgd));uc.mem_write(m+224,struct.pack('<I',7))
            trace.clear();uc.reg_write(UC_ARM64_REG_X0,dst);uc.reg_write(UC_ARM64_REG_X1,src);uc.reg_write(UC_ARM64_REG_X30,stop);uc.reg_write(UC_ARM64_REG_SP,stack);uc.reg_write(UC_ARM64_REG_SP_EL0,task)
            try:uc.emu_start(kernel.address('copy_page_range'),stop,count=100000)
            except Exception as error:raise RuntimeError(f'case={case} PC={uc.reg_read(UC_ARM64_REG_PC):#x} trace={trace}') from error
            assert uc.reg_read(UC_ARM64_REG_PC)==stop and uc.reg_read(UC_ARM64_REG_X0)==0
            actual=[struct.unpack('<Q',uc.mem_read(v+32,8))[0] for v in (src,dst)]+[struct.unpack('<I',uc.mem_read(v+44,4))[0] for v in (src,dst)]
            assert actual==list(out),('flags/seq',case,actual,list(out))
            assert trace==expected,('split/lock order',case,trace,expected)
        print('PASS: 64 ARM64 copy_page_range hook cases; source/destination flag clear, split and VMA write-lock sequence')
        print('vma_needs_copy forced via PFNMAP; source tables empty, split modeled. Not PTE copying, VMA lifetime or fork concurrency proof.')


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--image',type=Path,required=True);p.add_argument('--symbols',type=Path,required=True);run(p.parse_args())
