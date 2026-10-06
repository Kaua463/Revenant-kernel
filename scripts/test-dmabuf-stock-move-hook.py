#!/usr/bin/env python3
"""Stock move caller routing and partial return; allocation/notifiers/PMD ops modeled."""
import argparse
import ctypes
import hashlib
from pathlib import Path
import struct
import subprocess
import tempfile
from importlib.machinery import SourceFileLoader


def load(name):
    return SourceFileLoader(name,str(Path(__file__).with_name(name))).load_module()


FIXTURE=r'''
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <assert.h>
typedef struct {uint64_t val;} pmd_t;
struct vm_area_struct {unsigned unused;};
#define HPAGE_PMD_SIZE (1UL<<21)
static pmd_t tables[4][512];static uint64_t rows[128][6];static unsigned nr,move_result;
static uint64_t canonical(pmd_t *p){return 0xffffff8001000000ULL+((uintptr_t)p-(uintptr_t)tables);}
static void trace(unsigned op,uint64_t a,uint64_t b,uint64_t c,uint64_t d,uint64_t e){assert(nr<128);uint64_t r[]={op,a,b,c,d,e};memcpy(rows[nr++],r,sizeof(r));}
static bool pmd_trans_huge(pmd_t p){return (p.val&0xc00000000000001ULL)&&!(p.val&2);}
static bool move_dmabuf_huge_pmd(struct vm_area_struct *v,uint64_t a,uint64_t b,pmd_t *p,pmd_t *q,bool locks){(void)v;trace(1,a,b,canonical(p),canonical(q),locks);if(move_result){q->val=p->val;p->val=0;}return move_result;}
static void __split_dmabuf_huge_pmd(struct vm_area_struct *v,pmd_t *p,uint64_t a,bool f,void *folio){(void)v;assert(!f&&!folio);trace(2,canonical(p),a,0,0,0);p->val=3;}
'''
WRAPPER=r'''
uint64_t host_move(uint64_t start,uint64_t len,unsigned success,unsigned dest_present,unsigned locks,unsigned notifier,unsigned source_present,const void *pt,uint64_t *out,unsigned *n,void *out_pt){
 memcpy(tables,pt,sizeof(tables));nr=0;move_result=success;uint64_t a=start,b=start+(2ULL<<30),end=start+len;struct vm_area_struct v={0};
 if(len&&notifier)trace(5,0x1001000,start,end,1,0);
 while(a<end){unsigned pg=(a>>30)&511;uint64_t extent=(1ULL<<30)-(a&((1ULL<<30)-1));if(extent>end-a)extent=end-a;
  if(source_present){extent=HPAGE_PMD_SIZE-(a&(HPAGE_PMD_SIZE-1));if(extent>end-a)extent=end-a;pmd_t *p=&tables[pg][(a>>21)&511],*q=&tables[pg+2][(b>>21)&511];
   if(p->val){if(!dest_present){trace(3,0x1001000,0x1002000+(pg+2)*8,b,0,0);break;}
    if(!dmabuf_huge_move_prepare(&v,a,b,p,q,extent,locks)&&p->val){trace(4,0x1001000,canonical(q),0,0,0);break;}
   }
  }
  a+=extent;b+=extent;
 }
 if(len&&notifier)trace(6,0x1001000,start,end,1,0);
 memcpy(out,rows,nr*6*sizeof(uint64_t));*n=nr;memcpy(out_pt,tables,sizeof(tables));return a-start;
}
'''


def run(args):
    from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE
    from unicorn.arm64_const import (UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X2,UC_ARM64_REG_X3,UC_ARM64_REG_X4,UC_ARM64_REG_X5,UC_ARM64_REG_X30,UC_ARM64_REG_SP,UC_ARM64_REG_SP_EL0,UC_ARM64_REG_PC)
    image=args.image.read_bytes();contract=load('verify-stock-recovered-contracts.py')
    assert hashlib.sha256(image).hexdigest()==contract.IMAGE_SHA and hashlib.sha256(args.symbols.read_bytes()).hexdigest()==contract.SYMBOL_SHA
    kernel=load('stock-binary-evidence.py').Kernel(args.image,args.symbols);fields=load('test-dmabuf-stock-wrappers.py').btf_fields
    for name,required in {'vm_area_struct':{'vm_mm':16,'vm_flags':32,'anon_vma':104,'vm_file':128},'mm_struct':{'pgd':112,'notifier_subscriptions':1056},'mmu_notifier_range':{'mm':0,'start':8,'end':16,'flags':24,'event':28,'owner':32}}.items():
        ident=next(i for i,t in enumerate(kernel.btf.types) if t['kind']==4 and t['name']==name);found=fields(kernel.btf,ident)
        for member,offset in required.items():assert found[member]==offset
    func=next(t for t in kernel.btf.types if t['kind']==12 and t['name']=='move_page_tables');proto=kernel.btf.types[func['size']]
    assert len(proto['raw'])==12 and kernel.btf.types[proto['size']]['name']=='unsigned long'
    for i,name in enumerate(('vm_area_struct','unsigned long','vm_area_struct','unsigned long','unsigned long','bool')):
        typ=kernel.btf.types[proto['raw'][i*2+1]]
        if i in (0,2):assert typ['kind']==2;typ=kernel.btf.types[typ['size']]
        assert typ['name']==name
    code=FIXTURE+(Path(__file__).parents[1]/'tools/stock-recovery/dmabuf_huge_move_hook.recovered.c').read_text()+WRAPPER
    with tempfile.TemporaryDirectory(prefix='dmabuf-move-hook-') as tmp:
        lib=Path(tmp)/'move.dylib';subprocess.run(['clang','-x','c','-std=c11','-Wall','-Wextra','-Werror','-dynamiclib','-o',str(lib),'-'],input=code,text=True,check=True)
        host=ctypes.CDLL(str(lib));host.host_move.argtypes=[ctypes.c_uint64]*2+[ctypes.c_uint]*5+[ctypes.c_void_p]*4;host.host_move.restype=ctypes.c_uint64
        uc=Uc(UC_ARCH_ARM64,UC_MODE_ARM);uc.mem_map(kernel.base,(len(image)+4095)&~4095);uc.mem_write(kernel.base,image)
        ram=0x1000000;uc.mem_map(ram,0x20000);vma=ram;mm=ram+0x1000;pgd=ram+0x2000;dst=ram+0x3000;task=ram+0x4000;stack=ram+0xf000;stop=ram+0x10000
        direct=0xffffff8001000000;uc.mem_map(direct,16384);uc.mem_write(kernel.address('memstart_addr'),bytes(8))
        ops={kernel.address('move_dmabuf_huge_pmd'):1,kernel.address('__split_dmabuf_huge_pmd'):2,kernel.address('__pmd_alloc'):3,kernel.address('__pte_alloc'):4,kernel.address('__mmu_notifier_invalidate_range_start'):5,kernel.address('__mmu_notifier_invalidate_range_end'):6}
        trace=[];state={'success':0};counts={i:0 for i in range(1,7)};partial=completed=zero=0
        def hook(emu,address,size,user):
            if address not in ops:return
            op=ops[address];x=[emu.reg_read(r) for r in (UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X2,UC_ARM64_REG_X3,UC_ARM64_REG_X4,UC_ARM64_REG_X5)];result=0
            if op==1:
                assert x[0]==vma;trace.append((op,*x[1:]));result=state['success']
                if result:emu.mem_write(x[4],bytes(emu.mem_read(x[3],8)));emu.mem_write(x[3],bytes(8))
            elif op==2:
                assert x[0]==vma and x[3:5]==[0,0];trace.append((op,x[1],x[2],0,0,0));emu.mem_write(x[1],struct.pack('<Q',3))
            elif op in (3,4):
                assert x[0]==mm;trace.append((op,x[0],x[1],x[2] if op==3 else 0,0,0));result=(1<<64)-12
            else:
                m,start,end,flags,event,owner=struct.unpack('<QQQIIQ',emu.mem_read(x[0],40));assert owner==0;trace.append((op,m,start,end,flags,event))
            emu.reg_write(UC_ARM64_REG_X0,result);emu.reg_write(UC_ARM64_REG_PC,emu.reg_read(UC_ARM64_REG_X30))
        uc.hook_add(UC_HOOK_CODE,hook);case=0
        for value in (0,1,3,1<<58,1<<59):
         for start,length in ((0,1<<21),(4096,4096),((1<<21)-4096,8192),((1<<30)-4096,8192),(0,(1<<21)+4096),(0,0)):
          for success in (0,1):
           for dest_present in (0,1):
            for locks in (0,1):
             for notifier in (0,1):
                source_present=case%13!=0;p=struct.pack('<2048Q',*([value]*1024+[0]*1024));out=(ctypes.c_uint64*(128*6))();n=ctypes.c_uint();op=ctypes.create_string_buffer(16384)
                expected_ret=host.host_move(start,length,success,dest_present,locks,notifier,source_present,ctypes.create_string_buffer(p),out,ctypes.byref(n),op)
                expected=[tuple(out[i*6:(i+1)*6]) for i in range(n.value)]
                uc.mem_write(mm,bytes(1600));uc.mem_write(mm+112,struct.pack('<Q',pgd));uc.mem_write(mm+1056,struct.pack('<Q',0x1234 if notifier else 0))
                for v in (vma,dst):uc.mem_write(v,bytes(208));uc.mem_write(v+16,struct.pack('<Q',mm));uc.mem_write(v+32,struct.pack('<Q',1<<39))
                pgds=[(0x1000000+i*4096)|3 if (source_present if i<2 else dest_present) else 0 for i in range(4)]
                uc.mem_write(pgd,struct.pack('<4Q',*pgds));uc.mem_write(direct,p);trace.clear();state['success']=success
                for r,v in zip((UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X2,UC_ARM64_REG_X3,UC_ARM64_REG_X4,UC_ARM64_REG_X5),(vma,start,dst,start+(2<<30),length,locks)):uc.reg_write(r,v)
                uc.reg_write(UC_ARM64_REG_X30,stop);uc.reg_write(UC_ARM64_REG_SP,stack);uc.reg_write(UC_ARM64_REG_SP_EL0,task)
                try:uc.emu_start(kernel.address('move_page_tables'),stop,count=100000)
                except Exception as error:raise RuntimeError(f'case={case} PC={uc.reg_read(UC_ARM64_REG_PC):#x} trace={trace[:12]}') from error
                assert uc.reg_read(UC_ARM64_REG_PC)==stop,('instruction bound',case)
                assert uc.reg_read(UC_ARM64_REG_X0)==expected_ret,('partial bytes',case,uc.reg_read(UC_ARM64_REG_X0),expected_ret)
                assert trace==expected,('route/order',case,trace,expected)
                assert bytes(uc.mem_read(direct,16384))==op.raw[:16384],('PMD outcome',case)
                for row in trace:counts[row[0]]+=1
                partial+=0<expected_ret<length;completed+=bool(length and expected_ret==length);zero+=not length;case+=1
        assert all(counts.values()) and partial and completed and zero,(counts,partial,completed,zero)
        print(f'PASS: {case} ARM64 move caller cases; routes={counts}; partial={partial}, complete={completed}, zero-length={zero}')
        print('DMA flag route only; PMD move/split, allocation failure and notifier bodies modeled. No populated PTE move, ownership, MMU or concurrency proof.')


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--image',type=Path,required=True);p.add_argument('--symbols',type=Path,required=True);run(p.parse_args())
