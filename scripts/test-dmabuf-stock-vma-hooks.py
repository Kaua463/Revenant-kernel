#!/usr/bin/env python3
"""Stock vma_expand/shrink with no adjacent VMA; tree/locks/adjust helpers modeled."""
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
struct vm_area_struct {uint64_t vm_start,vm_end,vm_flags,vm_pgoff;unsigned seq;};
static uint64_t rows[16][4];static unsigned nr;
static void trace(unsigned op,struct vm_area_struct *v,uint64_t x){rows[nr][0]=op;rows[nr][1]=v->vm_start;rows[nr][2]=v->vm_end;rows[nr++][3]=x;}
static void vma_adjust_dmabuf_huge(struct vm_area_struct *v,uint64_t a,uint64_t b,long adj){(void)a;(void)b;(void)adj;trace(2,v,0);}
static void vma_adjust_trans_huge(struct vm_area_struct *v,uint64_t a,uint64_t b,long adj){(void)a;(void)b;(void)adj;trace(3,v,0);}
'''
WRAPPER=r'''
unsigned host_vma(const uint64_t *in,uint64_t *out,uint64_t *trace_out){
 struct vm_area_struct v={0x400000,0x800000,in[0],0xabc,in[1]};nr=0;unsigned shrink=in[2],fail=in[3];uint64_t start=in[4],end=in[5],off=in[6];
 if(!shrink&&v.seq!=7){trace(6,&v,0);v.seq=7;trace(7,&v,0);}
 trace(0,&v,shrink?0:0x1000000);
 if(!fail){if(shrink&&v.seq!=7){trace(6,&v,0);v.seq=7;trace(7,&v,0);}
  trace(1,&v,0);dmabuf_huge_adjust_prepare(&v,start,end);
  if(shrink)trace(4,&v,0);
  v.vm_start=start;v.vm_end=end;v.vm_pgoff=off;
  if(!shrink)trace(4,&v,0x1000000);
  trace(5,&v,0);
 }
 out[0]=v.vm_start;out[1]=v.vm_end;out[2]=v.vm_pgoff;out[3]=v.seq;out[4]=fail?0xfffffff4:0;
 memcpy(trace_out,rows,nr*4*sizeof(uint64_t));return nr;
}
'''


def run(args):
    from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE
    from unicorn.arm64_const import (UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X2,UC_ARM64_REG_X3,UC_ARM64_REG_X4,UC_ARM64_REG_X5,UC_ARM64_REG_X30,UC_ARM64_REG_SP,UC_ARM64_REG_SP_EL0,UC_ARM64_REG_PC)
    image=args.image.read_bytes();contract=load('verify-stock-recovered-contracts.py')
    assert hashlib.sha256(image).hexdigest()==contract.IMAGE_SHA and hashlib.sha256(args.symbols.read_bytes()).hexdigest()==contract.SYMBOL_SHA
    kernel=load('stock-binary-evidence.py').Kernel(args.image,args.symbols);fields=load('test-dmabuf-stock-wrappers.py').btf_fields
    for name,required in {'vm_area_struct':{'vm_start':0,'vm_end':8,'vm_mm':16,'vm_flags':32,'vm_lock_seq':44,'vm_lock':48,'vm_pgoff':120},'mm_struct':{'mm_lock_seq':224},'ma_state':{'index':8,'last':16,'node':24}}.items():
        ident=next(i for i,t in enumerate(kernel.btf.types) if t['kind']==4 and t['name']==name);found=fields(kernel.btf,ident)
        for member,offset in required.items():assert found[member]==offset
    for name,count in (('vma_expand',6),('vma_shrink',5)):
        func=next(t for t in kernel.btf.types if t['kind']==12 and t['name']==name);proto=kernel.btf.types[func['size']]
        assert len(proto['raw'])==count*2 and kernel.btf.types[proto['size']]['name']=='int'
    code=FIXTURE+(Path(__file__).parents[1]/'tools/stock-recovery/dmabuf_huge_vma_hook.recovered.c').read_text()+WRAPPER
    with tempfile.TemporaryDirectory(prefix='dmabuf-vma-hooks-') as tmp:
        lib=Path(tmp)/'vma.dylib';subprocess.run(['clang','-x','c','-std=c11','-Wall','-Wextra','-Werror','-dynamiclib','-o',str(lib),'-'],input=code,text=True,check=True)
        host=ctypes.CDLL(str(lib));host.host_vma.argtypes=[ctypes.c_void_p]*3;host.host_vma.restype=ctypes.c_uint
        uc=Uc(UC_ARCH_ARM64,UC_MODE_ARM);uc.mem_map(kernel.base,(len(image)+4095)&~4095);uc.mem_write(kernel.base,image)
        ram=0x1000000;uc.mem_map(ram,0x20000);vma=ram;mm=ram+0x1000;iterator=ram+0x2000;sem=ram+0x3000;task=ram+0x4000;stack=ram+0xf000;stop=ram+0x10000
        ops={kernel.address('mas_preallocate'):0,kernel.address('vma_prepare'):1,kernel.address('vma_adjust_dmabuf_huge'):2,kernel.address('vma_adjust_trans_huge'):3,kernel.address('mas_store_prealloc'):4,kernel.address('vma_complete'):5,kernel.address('down_write'):6,kernel.address('up_write'):7}
        trace=[];state={};counts={i:0 for i in range(8)}
        def hook(emu,address,size,user):
            if address not in ops:return
            op=ops[address];x=[emu.reg_read(r) for r in (UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X2,UC_ARM64_REG_X3)]
            start,end=struct.unpack('<2Q',emu.mem_read(vma,16));value=0
            if op in (0,4):assert x[0]==iterator;value=x[1]
            elif op in (1,5):assert struct.unpack('<Q',emu.mem_read(x[0],8))[0]==vma
            elif op in (2,3):assert x==[vma,state['start'],state['end'],0]
            else:assert x[0]==sem
            trace.append((op,start,end,value));emu.reg_write(UC_ARM64_REG_X0,1 if op==0 and state['fail'] else 0);emu.reg_write(UC_ARM64_REG_PC,emu.reg_read(UC_ARM64_REG_X30))
        uc.hook_add(UC_HOOK_CODE,hook);case=0
        for shrink in (0,1):
         for dma in (0,1):
          for fail in (0,1):
           for seq in (0,7,8):
            for change_start in (0,1):
                start=0x400000+(4096 if shrink else -4096) if change_start else 0x400000
                end=0x800000 if change_start else 0x800000+(-4096 if shrink else 4096)
                inputs=(ctypes.c_uint64*7)(dma<<39,seq,shrink,fail,start,end,0xdef+case);out=(ctypes.c_uint64*5)();rows=(ctypes.c_uint64*64)();n=host.host_vma(inputs,out,rows);expected=[tuple(rows[i*4:(i+1)*4]) for i in range(n)]
                uc.mem_write(vma,bytes(208));uc.mem_write(vma,struct.pack('<5Q',0x400000,0x800000,mm,0,dma<<39));uc.mem_write(vma+44,struct.pack('<I',seq));uc.mem_write(vma+48,struct.pack('<Q',sem));uc.mem_write(vma+120,struct.pack('<Q',0xabc));uc.mem_write(mm+224,struct.pack('<I',7))
                uc.mem_write(iterator,bytes(128));uc.mem_write(iterator+24,struct.pack('<Q',1));trace.clear();state.update(start=start,end=end,fail=fail)
                for r,v in zip((UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X2,UC_ARM64_REG_X3,UC_ARM64_REG_X4,UC_ARM64_REG_X5),(iterator,vma,start,end,0xdef+case,0)):uc.reg_write(r,v)
                uc.reg_write(UC_ARM64_REG_X30,stop);uc.reg_write(UC_ARM64_REG_SP,stack);uc.reg_write(UC_ARM64_REG_SP_EL0,task)
                try:uc.emu_start(kernel.address('vma_shrink' if shrink else 'vma_expand'),stop,count=100000)
                except Exception as error:raise RuntimeError(f'case={case} PC={uc.reg_read(UC_ARM64_REG_PC):#x} trace={trace}') from error
                assert uc.reg_read(UC_ARM64_REG_PC)==stop
                actual=list(struct.unpack('<2Q',uc.mem_read(vma,16)))+[struct.unpack('<Q',uc.mem_read(vma+120,8))[0],struct.unpack('<I',uc.mem_read(vma+44,4))[0],uc.reg_read(UC_ARM64_REG_X0)&0xffffffff]
                assert actual==list(out),('state',case,actual,list(out));assert trace==expected,('order',case,trace,expected)
                for row in trace:counts[row[0]]+=1
                case+=1
        assert all(counts.values()),counts
        print(f'PASS: {case} ARM64 expand/shrink cases; no adjacent VMA, routes={counts}; boundary-update/prepare/adjust/store order and allocation failure')
        print('Maple-tree, VMA locks and adjust bodies modeled. No merging/anon cloning, actual page-table split or concurrency/lifetime proof.')


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--image',type=Path,required=True);p.add_argument('--symbols',type=Path,required=True);run(p.parse_args())
