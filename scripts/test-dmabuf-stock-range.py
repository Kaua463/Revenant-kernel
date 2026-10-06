#!/usr/bin/env python3
"""Exact stock range-walker routing/BUG guard, with split helper modeled."""
import argparse
import ctypes
import hashlib
from pathlib import Path
import random
import struct
import subprocess
import tempfile
from importlib.machinery import SourceFileLoader


FIXTURE = r'''
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <setjmp.h>
typedef struct { uint64_t val; } pgd_t,pmd_t;
struct mm_struct { pgd_t *pgd; };
struct vm_area_struct { uint64_t vm_start,vm_end;struct mm_struct *vm_mm;uint64_t vm_flags; };
static struct mm_struct mm;static pgd_t pgds[4];static pmd_t tables[4][512];
static uint64_t rows[2048][3];static unsigned nr,bug;static jmp_buf trap;
#define BUG_ON(x) do {if(x){bug=1;longjmp(trap,1);}} while(0)
#define pgd_val(p) ((p).val)
static pgd_t *pgd_offset(struct mm_struct *m,uint64_t a){return m->pgd+((a>>30)&511);}
static uint64_t addr_end(uint64_t a,uint64_t e,uint64_t size){uint64_t n=(a&~(size-1))+size;return n-1<e-1?n:e;}
#define pgd_addr_end(a,e) addr_end(a,e,1ULL<<30)
#define pmd_addr_end(a,e) addr_end(a,e,1ULL<<21)
static void *__va(uint64_t pa){assert(pa>=0x1000000 && pa<0x1004000 && !(pa&4095));return tables[(pa-0x1000000)>>12];}
static int pmd_trans_huge(pmd_t p){return (p.val&0xc00000000000001ULL) && !(p.val&2);}
static void __split_dmabuf_huge_pmd(struct vm_area_struct *v,pmd_t *p,uint64_t a,bool f,void *folio){
 (void)v;assert(!f && !folio && nr<2048);
 rows[nr][0]=0xffffff8001000000ULL+((uintptr_t)p-(uintptr_t)tables);
 rows[nr][1]=a;rows[nr++][2]=0;
}
'''
WRAPPER = r'''
unsigned host_range(uint64_t start,uint64_t end,uint64_t flags,const void *g,const void *p,uint64_t *out) {
 memcpy(pgds,g,sizeof(pgds));memcpy(tables,p,sizeof(tables));mm.pgd=pgds;
 struct vm_area_struct v={start,end,&mm,flags};nr=bug=0;
 if(!setjmp(trap))split_dmabuf_huge_range(&v);
 memcpy(out,rows,nr*3*sizeof(uint64_t));return nr|(bug<<31);
}
'''


def load(name):
    return SourceFileLoader(name,str(Path(__file__).with_name(name))).load_module()


def run(args):
    from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE
    from unicorn.arm64_const import (UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X2,
                                    UC_ARM64_REG_X3,UC_ARM64_REG_X4,UC_ARM64_REG_X30,
                                    UC_ARM64_REG_SP,UC_ARM64_REG_PC)
    image=args.image.read_bytes();contract=load('verify-stock-recovered-contracts.py')
    assert hashlib.sha256(image).hexdigest()==contract.IMAGE_SHA
    assert hashlib.sha256(args.symbols.read_bytes()).hexdigest()==contract.SYMBOL_SHA
    kernel=load('stock-binary-evidence.py').Kernel(args.image,args.symbols)
    btf=kernel.btf;fields=load('test-dmabuf-stock-wrappers.py').btf_fields
    for name,required in {'vm_area_struct':{'vm_start':0,'vm_end':8,'vm_mm':16,'vm_flags':32},'mm_struct':{'pgd':112}}.items():
        ident=next(i for i,t in enumerate(btf.types) if t['kind']==4 and t['name']==name)
        found=fields(btf,ident)
        for member,offset in required.items():assert found[member]==offset
    code=FIXTURE+(Path(__file__).parents[1]/'tools/stock-recovery/dmabuf_huge_range.recovered.c').read_text()+WRAPPER
    with tempfile.TemporaryDirectory(prefix='dmabuf-range-') as tmp:
        lib=Path(tmp)/'range.dylib'
        subprocess.run(['clang','-x','c','-std=c11','-Wall','-Wextra','-Werror','-dynamiclib','-o',str(lib),'-'],input=code,text=True,check=True)
        host=ctypes.CDLL(str(lib));host.host_range.argtypes=[ctypes.c_uint64]*3+[ctypes.c_void_p]*3;host.host_range.restype=ctypes.c_uint
        uc=Uc(UC_ARCH_ARM64,UC_MODE_ARM);uc.mem_map(kernel.base,(len(image)+4095)&~4095);uc.mem_write(kernel.base,image)
        ram=0x1000000;uc.mem_map(ram,0x20000)
        vma,mm,pgd,stack,stop=[ram+x for x in (0,0x1000,0x2000,0xf000,0x10000)]
        direct=0xffffff8001000000;uc.mem_map(direct,4*4096)
        uc.mem_write(kernel.address('memstart_addr'),bytes(8))
        trace=[];state={'bug':False}
        split=kernel.address('__split_dmabuf_huge_pmd')
        def hook(emu,address,size,user):
            if address==split:
                x=[emu.reg_read(r) for r in (UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X2,UC_ARM64_REG_X3,UC_ARM64_REG_X4)]
                assert x[0]==vma and x[3:]==[0,0]
                trace.append((x[1],x[2],0));emu.reg_write(UC_ARM64_REG_PC,emu.reg_read(UC_ARM64_REG_X30))
            elif kernel.base<=address<kernel.base+len(image):
                word=struct.unpack_from('<I',image,address-kernel.base)[0]
                if word&0xffe0001f==0xd4200000:
                    state['bug']=True;emu.emu_stop()
        uc.hook_add(UC_HOOK_CODE,hook);rng=random.Random(0x3043);bugs=0
        for case in range(args.cases):
            start=(0,(1<<30)-4096,(1<<21)-4096)[case] if case<3 else rng.randrange(0,3<<30)&~4095
            end=min(4<<30,start+(1<<30 if case%31==0 else rng.randrange(1,20000)*4096))
            flags=rng.getrandbits(64)|1<<39
            if case%5==0:flags&=~(1<<39)
            pgds=[(0x1000000+i*4096)|((case+i)%4) for i in range(4)]
            tables=[0x4000000|(0,1,3,1<<58,1<<59)[rng.randrange(5)] for _ in range(2048)]
            g=struct.pack('<4Q',*pgds);p=struct.pack('<2048Q',*tables)
            out=(ctypes.c_uint64*(2048*3))();gb=ctypes.create_string_buffer(g);pb=ctypes.create_string_buffer(p)
            result=host.host_range(start,end,flags,gb,pb,out);n=result&0x7fffffff
            expected=[tuple(out[i*3:(i+1)*3]) for i in range(n)]
            uc.mem_write(vma,struct.pack('<5Q',start,end,mm,0,flags));uc.mem_write(mm+112,struct.pack('<Q',pgd))
            uc.mem_write(pgd,g);uc.mem_write(direct,p);trace.clear();state['bug']=False
            uc.reg_write(UC_ARM64_REG_X0,vma);uc.reg_write(UC_ARM64_REG_X30,stop);uc.reg_write(UC_ARM64_REG_SP,stack)
            uc.emu_start(kernel.address('split_dmabuf_huge_range'),stop,count=100000)
            assert state['bug']==bool(result>>31),('guard',case)
            assert state['bug'] or uc.reg_read(UC_ARM64_REG_PC)==stop,'instruction bound'
            assert trace==expected,('routing',case,trace[:4],expected[:4])
            assert bytes(uc.mem_read(direct,len(p)))==p,'walker must not mutate table when helper modeled'
            bugs+=state['bug']
        print(f'PASS: {args.cases} stock ARM64 range cases; PGD/PMD routing, boundary stops and {bugs} VMA bit-39 BUG guards')
        print('Split helper intercepted; does not prove page-table stability, MMU or flag producer contract.')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image',type=Path,required=True);parser.add_argument('--symbols',type=Path,required=True)
    parser.add_argument('--cases',type=int,default=500);run(parser.parse_args())
