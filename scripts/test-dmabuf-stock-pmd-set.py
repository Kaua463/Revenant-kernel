#!/usr/bin/env python3
"""Exact ACK pmd_set_huge/attribute-safety bodies against original ARM64."""
import argparse
import ctypes
import hashlib
from pathlib import Path
import random
import struct
import subprocess
import tempfile
from importlib.machinery import SourceFileLoader


def load(name):
    return SourceFileLoader(name,str(Path(__file__).with_name(name))).load_module()


FIXTURE=r'''
#include <stdbool.h>
#include <stdint.h>
typedef uint64_t u64,pteval_t,phys_addr_t;
typedef struct {uint64_t val;} pmd_t,pte_t,pgprot_t;
static unsigned barriers;
#define PTE_PXN (1ULL<<53)
#define PTE_RDONLY (1ULL<<7)
#define PTE_WRITE (1ULL<<51)
#define PTE_NG (1ULL<<11)
#define PTE_CONT (1ULL<<52)
#define PTE_ATTRINDX_MASK 28ULL
#define PTE_ATTRINDX(x) ((uint64_t)(x)<<2)
#define MT_NORMAL 0
#define MT_NORMAL_TAGGED 1
#define __pte(x) ((pte_t){x})
#define __pmd(x) ((pmd_t){x})
#define pte_valid(x) ((x).val&1)
#define pte_pfn(x) (((x).val&0xfffffffff000ULL)>>12)
#define pmd_val(x) ((x).val)
#define READ_ONCE(x) (x)
#define __phys_to_pfn(x) ((x)>>12)
#define pfn_pmd(p,prot) __pmd(((p)<<12)|(prot).val)
#define PMD_MASK (~((1ULL<<21)-1))
/* DEBUG_VM=n in pinned stock; this is explicitly not an alignment guard. */
#define VM_BUG_ON(x) ((void)(x))
static pgprot_t mk_pmd_sect_prot(pgprot_t p){p.val=(p.val&~3ULL)|1;return p;}
static void set_pmd(pmd_t *p,pmd_t v){*p=v;if(v.val&1)barriers+=2;}
'''
WRAPPER=r'''
unsigned host_pmd(uint64_t old,uint64_t phys,uint64_t prot,uint64_t *out){
 pmd_t p={old};barriers=0;int ret=pmd_set_huge(&p,phys,(pgprot_t){prot});out[0]=p.val;out[1]=barriers;return ret;}
'''


def run(args):
    from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE
    from unicorn.arm64_const import UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X2,UC_ARM64_REG_X30,UC_ARM64_REG_SP,UC_ARM64_REG_PC
    source=args.source.read_text();assert hashlib.sha256(args.source.read_bytes()).hexdigest()=='5faec6be3b00796e2a4693d0892fe6b2684c34712eeeb7ca0b5d1a8e1707d89b'
    extract=load('test-dmabuf-stock-deposit.py').body
    functions=extract(source,'bool pgattr_change_is_safe(')+'\n'+extract(source,'int pmd_set_huge(')
    image=args.image.read_bytes();contract=load('verify-stock-recovered-contracts.py')
    assert hashlib.sha256(image).hexdigest()==contract.IMAGE_SHA and hashlib.sha256(args.symbols.read_bytes()).hexdigest()==contract.SYMBOL_SHA
    kernel=load('stock-binary-evidence.py').Kernel(args.image,args.symbols)
    assert kernel.cfg['CONFIG_DEBUG_VM']=='n' and kernel.cfg['CONFIG_ARM64_4K_PAGES']=='y'
    with tempfile.TemporaryDirectory(prefix='dmabuf-pmd-set-') as tmp:
        lib=Path(tmp)/'pmd.dylib';subprocess.run(['clang','-x','c','-std=c11','-Wall','-Wextra','-Werror','-dynamiclib','-o',str(lib),'-'],input=FIXTURE+functions+WRAPPER,text=True,check=True)
        host=ctypes.CDLL(str(lib));host.host_pmd.argtypes=[ctypes.c_uint64]*3+[ctypes.c_void_p];host.host_pmd.restype=ctypes.c_uint
        uc=Uc(UC_ARCH_ARM64,UC_MODE_ARM);uc.mem_map(kernel.base,(len(image)+4095)&~4095);uc.mem_write(kernel.base,image)
        ram=0x1000000;uc.mem_map(ram,0x20000);pmd=ram;stack=ram+0xf000;stop=ram+0x10000;trace=[]
        def hook(emu,address,size,user):
            if kernel.base<=address<kernel.base+len(image):
                word=struct.unpack_from('<I',image,address-kernel.base)[0]
                if word in (0xd5033a9f,0xd5033fdf):trace.append(word)
        uc.hook_add(UC_HOOK_CODE,hook);rng=random.Random(0x304a);accepted=rejected=unaligned=0
        for case in range(3000):
            phys=rng.getrandbits(48)&~4095
            base_prot=1|((case%8)<<2)|(((case>>3)&1)<<11)|(((case>>4)&1)<<52)|(((case>>5)&1)<<7)|(((case>>6)&1)<<51)|(((case>>7)&1)<<53)
            old=phys|base_prot
            prot=base_prot ^ (1<<(7,11,51,52,53,54,56,2)[case%8])
            if case%5==0:old=0
            if case%7==0:phys+=4096
            if case%11==0:phys+=1
            if case%13==0:prot=base_prot
            out=(ctypes.c_uint64*2)();expected=host.host_pmd(old,phys,prot,out)
            uc.mem_write(pmd,struct.pack('<Q',old));trace.clear()
            for r,v in zip((UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X2),(pmd,phys,prot)):uc.reg_write(r,v)
            uc.reg_write(UC_ARM64_REG_X30,stop);uc.reg_write(UC_ARM64_REG_SP,stack)
            uc.emu_start(kernel.address('pmd_set_huge'),stop,count=10000)
            assert uc.reg_read(UC_ARM64_REG_PC)==stop
            actual=struct.unpack('<Q',uc.mem_read(pmd,8))[0]
            assert actual==out[0] and uc.reg_read(UC_ARM64_REG_X0)==expected,('result/PMD',case,old,phys,prot,actual,out[0])
            assert trace==([0xd5033a9f,0xd5033fdf] if out[1] else []),('barrier',case)
            accepted+=bool(expected);rejected+=not expected;unaligned+=bool(expected) and bool(phys&((1<<21)-1))
        assert accepted and rejected and unaligned
        print(f'PASS: 3000 stock ARM64 pmd_set_huge cases vs exact ACK bodies; accepted={accepted}, rejected={rejected}, accepted_non_2MiB_aligned={unaligned}')
        print('DEBUG_VM=n removes VM_BUG_ON alignment check. API callers must prove suitability; no MMU/SMP claim.')


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--image',type=Path,required=True);p.add_argument('--symbols',type=Path,required=True);p.add_argument('--source',type=Path,required=True);run(p.parse_args())
