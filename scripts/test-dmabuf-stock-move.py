#!/usr/bin/env python3
"""Stock move vs recovered C; first CPU variant: range-TLBI disabled."""
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
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <setjmp.h>
typedef struct {uint64_t val;} pmd_t;
typedef void spinlock_t;typedef void *pgtable_t;
struct mm_struct {uint64_t asid;bool notifier;};
struct file {void *f_mapping;};
struct vm_area_struct {struct mm_struct *vm_mm;struct file *vm_file;void *anon_vma;};
static struct mm_struct mm;static struct file file;static pmd_t entries[1024];
static uint64_t rows[64][4],caps;static unsigned nr,bug;static jmp_buf trap;
#define HPAGE_PMD_SIZE (1UL<<21)
#define BUG_ON(x) do{if(x){bug=1;longjmp(trap,1);}}while(0)
static void trace(uint64_t op,uint64_t a,uint64_t b,uint64_t c){assert(nr<64);uint64_t row[]={op,a,b,c};memcpy(rows[nr++],row,sizeof(row));}
static void i_mmap_lock_write(void *m){(void)m;trace(1,0x1008090,0,0);}
static void i_mmap_unlock_write(void *m){(void)m;trace(2,0x1008090,0,0);}
static void anon_vma_lock_write(void *a){(void)a;trace(1,0x1009008,0,0);}
static void anon_vma_unlock_write(void *a){(void)a;trace(2,0x1009008,0,0);}
static void *pmd_ptdesc(pmd_t *p){return (void *)(0xfffffffe00040000ULL+((p-entries)/512)*64);}
static spinlock_t *ptlock_ptr(void *d){return (void *)((uintptr_t)d+40);}
static void spin_lock(spinlock_t *p){trace(3,(uintptr_t)p,0,0);}
static void spin_unlock(spinlock_t *p){trace(4,(uintptr_t)p,0,0);}
static int pmd_none(pmd_t p){return !p.val;}
static int pmd_present(pmd_t p){return !!(p.val&0xc00000000000001ULL);}
static spinlock_t *__pmd_dmabuf_huge_lock(pmd_t *p,struct vm_area_struct *v){(void)v;spinlock_t *l=ptlock_ptr(pmd_ptdesc(p));spin_lock(l);if(!pmd_present(*p)||(p->val&2)){spin_unlock(l);return NULL;}return l;}
static pmd_t pmdp_huge_get_and_clear(struct mm_struct *m,unsigned long a,pmd_t *p){(void)m;(void)a;pmd_t old=*p;p->val=0;return old;}
static uint64_t pmd_addr(pmd_t *p){return 0xffffff8001000000ULL+(p-entries)*8;}
static pgtable_t pgtable_trans_huge_withdraw(struct mm_struct *m,pmd_t *p){assert(m==&mm);trace(5,0x1001000,pmd_addr(p),0);return (void *)0xfffffffe00050000ULL;}
static void pgtable_trans_huge_deposit(struct mm_struct *m,pmd_t *p,pgtable_t t){assert(m==&mm);trace(6,0x1001000,pmd_addr(p),(uintptr_t)t);}
static void barrier(uint64_t word){trace(9,word,0,0);}
static void set_pmd_at(struct mm_struct *m,unsigned long a,pmd_t *p,pmd_t v){(void)m;(void)a;
 if((v.val&0x400000000000001ULL)&&!(v.val&0x140000000000000ULL))trace(7,v.val,0,0);
 if((v.val&0x10000000000005dULL)==0x45 && (caps&(1ULL<<53)))trace(8,v.val,512,0);
 p->val=v.val;if((v.val&0x40000000000041ULL)==0x40000000000001ULL){barrier(0xd5033a9f);barrier(0xd5033fdf);}}
static void flush_tlb_range(struct vm_area_struct *v,unsigned long start,unsigned long end){
 (void)start;(void)end;assert(v->vm_mm==&mm);barrier(0xd5033a9f);
 uint64_t asid=mm.asid<<48;trace(10,0xd5088340,asid,0);
 if(caps&1)trace(10,0xd5088340,asid|(1ULL<<48),0);
 barrier(0xd5033b9f);if(mm.notifier)trace(11,0x1001000,0,~0ULL);barrier(0xd5033b9f);}
'''
WRAPPER=r'''
unsigned host_move(const uint64_t *in,uint64_t *out,uint64_t *trace_out){
 nr=bug=0;memset(entries,0,sizeof(entries));entries[1].val=in[0];unsigned new_index=in[1]?513:2;entries[new_index].val=in[2];
 mm.asid=in[3];mm.notifier=in[4];caps=(in[5]<<53)|in[6];file.f_mapping=(void *)1;
 struct vm_area_struct v={&mm,in[7]?&file:NULL,in[8]?(void *)1:NULL};bool ret=false;
 if(!setjmp(trap))ret=move_dmabuf_huge_pmd(&v,in[9],0x20000000,entries+1,entries+new_index,in[10]);
 out[0]=ret;out[1]=entries[1].val;out[2]=entries[new_index].val;out[3]=bug;memcpy(trace_out,rows,nr*4*sizeof(uint64_t));return nr;
}
'''


def run(args):
    from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE
    from unicorn.arm64_const import (UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X2,UC_ARM64_REG_X3,UC_ARM64_REG_X4,UC_ARM64_REG_X5,UC_ARM64_REG_X30,UC_ARM64_REG_SP,UC_ARM64_REG_PC)
    image=args.image.read_bytes();contract=load('verify-stock-recovered-contracts.py')
    assert hashlib.sha256(image).hexdigest()==contract.IMAGE_SHA and hashlib.sha256(args.symbols.read_bytes()).hexdigest()==contract.SYMBOL_SHA
    kernel=load('stock-binary-evidence.py').Kernel(args.image,args.symbols)
    btf=kernel.btf;fields=load('test-dmabuf-stock-wrappers.py').btf_fields
    for name,wanted in {'vm_area_struct':{'vm_mm':16,'anon_vma':104,'vm_file':128},
                        'mm_struct':{'notifier_subscriptions':0x420,'context':0x3c8},
                        'file':{'f_mapping':232},'address_space':{'i_mmap_rwsem':144},
                        'anon_vma':{'root':0,'rwsem':8},'ptdesc':{'ptl':40}}.items():
        ident=next(i for i,t in enumerate(btf.types) if t['kind']==4 and t['name']==name)
        actual=fields(btf,ident)
        for member,offset in wanted.items():assert actual[member]==offset,(name,member,actual.get(member))
    func=next(t for t in btf.types if t['kind']==12 and t['name']=='move_dmabuf_huge_pmd')
    proto=btf.types[func['size']];assert len(proto['raw'])==12 and btf.types[proto['size']]['name']=='bool'
    params=[btf.types[proto['raw'][i+1]] for i in range(0,12,2)]
    assert params[0]['kind']==2 and btf.types[params[0]['size']]['name']=='vm_area_struct'
    assert [p['name'] for p in params[1:3]]==['unsigned long','unsigned long']
    assert all(p['kind']==2 and btf.types[p['size']]['name']=='pmd_t' for p in params[3:5]) and params[5]['name']=='bool'
    code=FIXTURE+(Path(__file__).parents[1]/'tools/stock-recovery/dmabuf_huge_move.recovered.c').read_text()+WRAPPER
    with tempfile.TemporaryDirectory(prefix='dmabuf-move-') as tmp:
        lib=Path(tmp)/'move.dylib';subprocess.run(['clang','-x','c','-std=c11','-Wall','-Wextra','-Werror','-dynamiclib','-o',str(lib),'-'],input=code,text=True,check=True)
        host=ctypes.CDLL(str(lib));host.host_move.argtypes=[ctypes.c_void_p]*3;host.host_move.restype=ctypes.c_uint
        uc=Uc(UC_ARCH_ARM64,UC_MODE_ARM);uc.mem_map(kernel.base,(len(image)+4095)&~4095);uc.mem_write(kernel.base,image)
        ram=0x1000000;uc.mem_map(ram,0x20000);vma,mm,file,mapping,anon,stack,stop=[ram+x for x in (0,0x1000,0x7000,0x8000,0x9000,0xf000,0x10000)]
        direct=0xffffff8001000000;uc.mem_map(direct,8192)
        cap=kernel.address('system_cpucaps');assert kernel.span('system_cpucaps') is None and kernel.symbols['system_cpucaps'][0][1]=='B';uc.mem_map(cap&~4095,4096)
        ops={'down_write':1,'up_write':2,'_raw_spin_lock':3,'_raw_spin_unlock':4,'pgtable_trans_huge_withdraw':5,'pgtable_trans_huge_deposit':6,'__sync_icache_dcache':7,'mte_sync_tags':8,'__mmu_notifier_arch_invalidate_secondary_tlbs':11}
        funcs={kernel.address(n):op for n,op in ops.items()};trace=[];state={}
        registers=(UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X2)
        def hook(emu,address,size,user):
            if address in funcs:
                op=funcs[address];count={1:1,2:1,3:1,4:1,5:2,6:3,7:1,8:2,11:3}[op]
                x=[emu.reg_read(r) for r in registers];trace.append((op,*[x[i] if i<count else 0 for i in range(3)]))
                emu.reg_write(UC_ARM64_REG_X0,0xfffffffe00050000 if op==5 else 0);emu.reg_write(UC_ARM64_REG_PC,emu.reg_read(UC_ARM64_REG_X30))
            elif kernel.base<=address<kernel.base+len(image):
                word=struct.unpack_from('<I',image,address-kernel.base)[0]
                if word&0xffe0001f==0xd4200000:state['bug']=1;emu.emu_stop()
                elif word in (0xd5033a9f,0xd5033fdf,0xd5033b9f):trace.append((9,word,0,0))
                elif word&~31 in (0xd5088340,0xd5088320,0xd5088220):
                    # TLBI effect is not emulated; retain opcode+operand.
                    reg=word&31;value=emu.reg_read(UC_ARM64_REG_X0+reg) if reg<31 else 0
                    trace.append((10,word&~31,value,0));emu.reg_write(UC_ARM64_REG_PC,address+4)
        uc.hook_add(UC_HOOK_CODE,hook)
        coverage={'moved':0,'rejected_old':0,'destination_bug':0,'rmap':0,'deposit_transfer':0,'icache':0,'mte':0,'paired_tlbi':0}
        for case in range(384):
            present=(1,3,0,1<<58,1<<59,0x45)[case%6]
            old=0x4000000|present|(((case>>1)&1)<<54)|(((case>>2)&1)<<56)
            if case%6==2:old=0
            values=(old,(case>>1)&1,int(case%23==0),case&0xffff,(case>>2)&1,(case>>3)&1,(case>>4)&1,(case>>5)&1,(case>>6)&1,0x400000+(4096 if case%2 else 0),(case>>7)&1)
            inputs=(ctypes.c_uint64*11)(*values);out=(ctypes.c_uint64*4)();rows=(ctypes.c_uint64*256)()
            n=host.host_move(inputs,out,rows);expected=[tuple(rows[i*4:(i+1)*4]) for i in range(n)]
            oldp=direct+8;newp=direct+(4104 if values[1] else 16)
            for a,v in ((vma+16,mm),(vma+104,anon if values[8] else 0),(vma+128,file if values[7] else 0),(file+232,mapping),(anon,anon),(mm+0x3c8,values[3]),(mm+0x420,values[4]),(oldp,old),(newp,values[2]),(cap,values[5]<<53),(cap+8,values[6])):uc.mem_write(a,struct.pack('<Q',v))
            trace.clear();state['bug']=0
            for r,v in zip((UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X2,UC_ARM64_REG_X3,UC_ARM64_REG_X4,UC_ARM64_REG_X5),(vma,values[9],0x20000000,oldp,newp,values[10])):uc.reg_write(r,v)
            uc.reg_write(UC_ARM64_REG_X30,stop);uc.reg_write(UC_ARM64_REG_SP,stack)
            try:uc.emu_start(kernel.address('move_dmabuf_huge_pmd'),stop,count=200000)
            except Exception as e:raise RuntimeError(f'case={case} PC={uc.reg_read(UC_ARM64_REG_PC):#x} trace={trace}') from e
            assert state['bug'] or uc.reg_read(UC_ARM64_REG_PC)==stop,'instruction bound'
            actual=[0 if state['bug'] else uc.reg_read(UC_ARM64_REG_X0),struct.unpack('<Q',uc.mem_read(oldp,8))[0],struct.unpack('<Q',uc.mem_read(newp,8))[0],state['bug']]
            assert actual==list(out),('writes/return',case,actual,list(out))
            assert trace==expected,('trace',case,trace,expected)
            coverage['moved']+=bool(out[0]);coverage['rejected_old']+=not out[0] and not out[3];coverage['destination_bug']+=bool(out[3])
            for category,op in (('rmap',1),('deposit_transfer',6),('icache',7),('mte',8)):
                coverage[category]+=any(row[0]==op for row in trace)
            coverage['paired_tlbi']+=sum(row[0]==10 for row in trace)>1
        assert all(coverage.values()),coverage
        print('PASS: 384 stock ARM64 move cases, range-TLBI disabled; PMD writes, same/different table locks, rmap locks, deposit transfer, cache/MTE helper and TLBI operands/barriers')
        print(f'Coverage categories: {coverage}')
        print('TLBI skipped after trace; helpers modeled. Range-TLBI, boot alternatives, SMP, MMU and lifetime not proven.')


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--image',type=Path,required=True);p.add_argument('--symbols',type=Path,required=True);run(p.parse_args())
