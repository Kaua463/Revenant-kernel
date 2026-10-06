#!/usr/bin/env python3
"""Stock unmap routing with empty PTE tables or a disappearing PMD; not MMU proof."""
import argparse
import ctypes
import hashlib
from pathlib import Path
import struct
import subprocess
import tempfile
from importlib.machinery import SourceFileLoader


def load(name):
    return SourceFileLoader(name, str(Path(__file__).with_name(name))).load_module()


FIXTURE = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
typedef struct {uint64_t val;} pmd_t;
struct mmu_gather {unsigned flags;};
struct vm_area_struct {uint64_t vm_flags;};
#define HPAGE_PMD_SIZE (1UL<<21)
static uint64_t rows[4096][3];static unsigned nr,zap_result;
static pmd_t tables[2][512];
static void trace(unsigned op,pmd_t *p,uint64_t a){assert(nr<4096);rows[nr][0]=op;rows[nr][1]=p?0xffffff8001000000ULL+((uintptr_t)p-(uintptr_t)tables):0;rows[nr++][2]=a;}
static bool pmd_trans_huge(pmd_t p){return (p.val&0xc00000000000001ULL)&&!(p.val&2);}
static int zap_dmabuf_huge_pmd(struct mmu_gather *t,struct vm_area_struct *v,pmd_t *p,uint64_t a){(void)t;(void)v;trace(1,p,a);if(zap_result)p->val=0;return zap_result;}
static void zap_split_dmabuf_huge_pmd(struct vm_area_struct *v,pmd_t *p,uint64_t a,bool f,void *folio){(void)v;assert(!f&&!folio);trace(2,p,a);p->val=3;}
static uint64_t addr_end(uint64_t a,uint64_t e,uint64_t size){uint64_t n=(a&~(size-1))+size;return n-1<e-1?n:e;}
'''
WRAPPER = r'''
unsigned host_unmap(uint64_t start,uint64_t end,uint64_t flags,unsigned tlb_flags,unsigned ret,unsigned empty_ptes,const uint64_t *pgds,const void *pt,uint64_t *out,unsigned *out_flags,void *out_pt){
 struct vm_area_struct v={flags};struct mmu_gather t={tlb_flags};nr=0;zap_result=ret;memcpy(tables,pt,sizeof(tables));
 if(!(t.flags&1))t.flags=(t.flags&0xf8ff)|((flags&4)<<6)|((!!(flags&0x10000400ULL))<<10);
 for(uint64_t a=start;a<end;){uint64_t pg_end=addr_end(a,end,1ULL<<30);unsigned pg=(a>>30)&511;assert(pg<2);
  if((pgds[pg]&3)==3){do{uint64_t next=addr_end(a,pg_end,1ULL<<21);pmd_t *p=&tables[pg][(a>>21)&511];bool consumed=false;
   if(flags&(1ULL<<39))consumed=dmabuf_huge_unmap_prepare(&t,&v,p,a,next);
   else if(p->val && (!(p->val&0xc00000000000001ULL)||!(p->val&2)||(p->val&(1ULL<<57)))){
    if(next-a==HPAGE_PMD_SIZE){trace(3,p,a);consumed=ret;if(ret)p->val=0;}
    else{trace(4,p,a);p->val=3;}
   }
   if(!consumed&&p->val){trace(5,p,a);if(empty_ptes){trace(7,NULL,0);trace(8,NULL,0);trace(9,NULL,0);}else p->val=0;}a=next;
  }while(a<pg_end);}
  a=pg_end;
 }
 if(!(t.flags&1))trace(6,NULL,0);
 memcpy(out,rows,nr*3*sizeof(uint64_t));*out_flags=t.flags;memcpy(out_pt,tables,sizeof(tables));return nr;
}
'''


def run(args):
    from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE
    from unicorn.arm64_const import (UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2,
                                    UC_ARM64_REG_X3, UC_ARM64_REG_X4, UC_ARM64_REG_X30,
                                    UC_ARM64_REG_SP, UC_ARM64_REG_SP_EL0, UC_ARM64_REG_PC)
    image = args.image.read_bytes(); contract = load('verify-stock-recovered-contracts.py')
    assert hashlib.sha256(image).hexdigest() == contract.IMAGE_SHA
    assert hashlib.sha256(args.symbols.read_bytes()).hexdigest() == contract.SYMBOL_SHA
    kernel = load('stock-binary-evidence.py').Kernel(args.image, args.symbols)
    fields = load('test-dmabuf-stock-wrappers.py').btf_fields
    for name, required in {'vm_area_struct': {'vm_mm':16,'vm_flags':32}, 'mm_struct': {'pgd':112}, 'mmu_gather': {'mm':0}}.items():
        ident = next(i for i,t in enumerate(kernel.btf.types) if t['kind']==4 and t['name']==name)
        found = fields(kernel.btf, ident)
        for member, offset in required.items(): assert found[member]==offset
    gather = next(t for t in kernel.btf.types if t['kind']==4 and t['name']=='mmu_gather')
    members = {kernel.btf.string(gather['raw'][i]):gather['raw'][i+2] for i in range(0,len(gather['raw']),3)}
    for member, bit in {'fullmm':256,'vma_exec':264,'vma_huge':265,'vma_pfn':266}.items():
        assert members[member]&0xffffff==bit and members[member]>>24==1
    funcs = [t for t in kernel.btf.types if t['kind']==12 and t['name']=='unmap_page_range']; assert len(funcs)==1
    proto = kernel.btf.types[funcs[0]['size']]; assert proto['size']==0 and len(proto['raw'])==10
    for i,name in enumerate(('mmu_gather','vm_area_struct','unsigned long','unsigned long','zap_details')):
        typ=kernel.btf.types[proto['raw'][i*2+1]]
        if i in (0,1,4): assert typ['kind']==2;typ=kernel.btf.types[typ['size']]
        assert typ['name']==name
    code = FIXTURE+(Path(__file__).parents[1]/'tools/stock-recovery/dmabuf_huge_unmap_hook.recovered.c').read_text()+WRAPPER
    with tempfile.TemporaryDirectory(prefix='dmabuf-unmap-') as tmp:
        lib=Path(tmp)/'unmap.dylib'; subprocess.run(['clang','-x','c','-std=c11','-Wall','-Wextra','-Werror','-dynamiclib','-o',str(lib),'-'],input=code,text=True,check=True)
        host=ctypes.CDLL(str(lib)); host.host_unmap.argtypes=[ctypes.c_uint64]*3+[ctypes.c_uint]*3+[ctypes.c_void_p]*5;host.host_unmap.restype=ctypes.c_uint
        uc=Uc(UC_ARCH_ARM64,UC_MODE_ARM);uc.mem_map(kernel.base,(len(image)+4095)&~4095);uc.mem_write(kernel.base,image)
        ram=0x1000000;uc.mem_map(ram,0x20000);vma=ram;mm=ram+0x1000;pgd=ram+0x2000;tlb=ram+0x3000;task=ram+0x4000;stack=ram+0xf000;stop=ram+0x10000
        direct=0xffffff8001000000;uc.mem_map(direct,8192);uc.mem_write(kernel.address('memstart_addr'),bytes(8))
        ops={kernel.address('zap_dmabuf_huge_pmd'):1,kernel.address('zap_split_dmabuf_huge_pmd'):2,kernel.address('zap_huge_pmd'):3,kernel.address('__split_huge_pmd'):4,kernel.address('__pte_offset_map_lock'):5,0xffffffc080330950:6,kernel.address('flush_tlb_batched_pending'):7,kernel.address('_raw_spin_unlock'):8,kernel.address('__rcu_read_unlock'):9}
        # Address-qualified local symbol; do not pick a different duplicate.
        assert any(line.split()[-1]=='tlb_flush_mmu_tlbonly' and int(line.split()[0],16)==0xffffffc080330950 for line in args.symbols.read_text().splitlines())
        trace=[];state={'ret':0,'bug':False,'empty_ptes':False};counts={i:0 for i in range(1,10)}
        def hook(emu,address,size,user):
            if address in ops:
                op=ops[address];x=[emu.reg_read(r) for r in (UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X2,UC_ARM64_REG_X3,UC_ARM64_REG_X4)]
                if op in (1,3):assert x[:2]==[tlb,vma];p,a=x[2:4]
                elif op in (2,4):assert x[0]==vma and x[3:]==[0,0];p,a=x[1:3]
                elif op==5:assert x[0]==mm;p,a=x[1:3]
                elif op==6:assert x[0]==tlb;p=a=0
                elif op==7:assert x[0]==mm;p=a=0
                elif op==8:assert x[0]==ram+0x5000;p=a=0
                else:p=a=0
                trace.append((op,p,a))
                if op in (1,3) and state['ret']:emu.mem_write(p,bytes(8))
                if op in (2,4):emu.mem_write(p,struct.pack('<Q',3))
                result=state['ret'] if op in (1,3) else 0
                if op==5:
                    if state['empty_ptes']:
                        emu.mem_write(x[3],struct.pack('<Q',ram+0x5000))
                        result=ram+0x11000+((a>>12)&511)*8
                    else:emu.mem_write(p,bytes(8))
                emu.reg_write(UC_ARM64_REG_X0,result)
                emu.reg_write(UC_ARM64_REG_PC,emu.reg_read(UC_ARM64_REG_X30))
            elif kernel.base<=address<kernel.base+len(image):
                word=struct.unpack_from('<I',image,address-kernel.base)[0]
                if word&0xffe0001f==0xd4200000:state['bug']=True;emu.emu_stop()
        uc.hook_add(UC_HOOK_CODE,hook)
        case=0
        for dma in (0,1):
          for value in (0,1,3,1<<58,1<<59,1<<57,4):
           for start,end in ((0,1<<21),(4096,1<<21),(0,4096),((1<<30)-4096,(1<<30)+4096),(0,3<<21)):
            for ret in (0,1):
             for fullmm in (0,1):
              for empty_ptes in (0,1):
                flags=0x400|(dma<<39)|((case%2)*4)|((case%3==0)*0x10000000);tf=0xffff&~1|fullmm
                pgds=(0x1000003,0x1001003) if case%11 else (0,0x1001003)
                g=struct.pack('<2Q',*pgds);p=struct.pack('<1024Q',*([value]*1024));out=(ctypes.c_uint64*(4096*3))();of=ctypes.c_uint();op=ctypes.create_string_buffer(8192)
                n=host.host_unmap(start,end,flags,tf,ret,empty_ptes,ctypes.create_string_buffer(g),ctypes.create_string_buffer(p),out,ctypes.byref(of),op)
                expected=[tuple(out[i*3:(i+1)*3]) for i in range(n)]
                uc.mem_write(vma,bytes(208));uc.mem_write(vma+16,struct.pack('<Q',mm));uc.mem_write(vma+32,struct.pack('<Q',flags));uc.mem_write(mm+112,struct.pack('<Q',pgd));uc.mem_write(pgd,g);uc.mem_write(direct,p)
                uc.mem_write(tlb,bytes(128));uc.mem_write(tlb,struct.pack('<Q',mm));uc.mem_write(tlb+32,struct.pack('<H',tf));trace.clear();state.update(ret=ret,bug=False,empty_ptes=empty_ptes)
                uc.mem_write(ram+0x11000,bytes(4096))
                for r,v in zip((UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X2,UC_ARM64_REG_X3,UC_ARM64_REG_X4),(tlb,vma,start,end,0)):uc.reg_write(r,v)
                uc.reg_write(UC_ARM64_REG_X30,stop);uc.reg_write(UC_ARM64_REG_SP,stack);uc.reg_write(UC_ARM64_REG_SP_EL0,task)
                try:uc.emu_start(kernel.address('unmap_page_range'),stop,count=100000)
                except Exception as error:raise RuntimeError(f'case={case} PC={uc.reg_read(UC_ARM64_REG_PC):#x} trace={trace}') from error
                assert not state['bug'] and uc.reg_read(UC_ARM64_REG_PC)==stop,('termination',case,hex(uc.reg_read(UC_ARM64_REG_PC)),state,trace[:12],len(trace))
                assert trace==expected,('routing',case,trace,expected)
                assert bytes(uc.mem_read(direct,8192))==op.raw[:8192],('PMD state',case)
                assert bytes(uc.mem_read(ram+0x11000,4096))==bytes(4096),('empty PTE state',case)
                assert struct.unpack('<H',uc.mem_read(tlb+32,2))[0]==of.value,('gather flags',case)
                for row in trace:counts[row[0]]+=1
                case+=1
        assert all(counts.values()),counts
        print(f'PASS: {case} ARM64 unmap caller cases; routing counts={counts}; gather flags, page-walk boundaries and modeled PMD outcomes')
        print('Empty PTE loop executes stock; NULL lookup separately models PMD disappearance/retry. PMD helpers/locks/flush modeled. Not populated PTE removal, MMU, freeing or lifetime proof.')


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--image',type=Path,required=True);p.add_argument('--symbols',type=Path,required=True);run(p.parse_args())
