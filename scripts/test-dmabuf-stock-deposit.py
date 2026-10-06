#!/usr/bin/env python3
"""Pinned ACK deposit/withdraw bodies vs stock ARM64: list bytes and ownership."""
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


def body(source, signature):
    assert source.count(signature)==1
    start=source.index(signature);opening=source.index('{',start);depth=1;end=opening+1
    while depth:
        depth+=(source[end]=='{')-(source[end]=='}');end+=1
    return source[start:end]


FIXTURE=r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <setjmp.h>
struct list_head {struct list_head *next,*prev;};
struct page {uint64_t flags;struct list_head lru;unsigned char rest[40];};
typedef struct page *pgtable_t;typedef struct {uint64_t val;} pmd_t;typedef unsigned spinlock_t;
struct mm_struct {int unused;};
static struct page pages[8];static unsigned char metadata[64];static unsigned bug;static jmp_buf trap;
static struct mm_struct mm;static pmd_t pmd;
#define pmd_huge_pte(mm,pmdp) (*(pgtable_t *)(metadata+16))
static spinlock_t *pmd_lockptr(struct mm_struct *m,pmd_t *p){(void)m;(void)p;return (unsigned *)(metadata+40);}
#define assert_spin_locked(p) do{if(!*(p)){bug=1;longjmp(trap,1);}}while(0)
static void INIT_LIST_HEAD(struct list_head *l){l->next=l->prev=l;}
static void list_add(struct list_head *l,struct list_head *h){struct list_head *n=h->next;
 assert(n->prev==h && l!=h && l!=n);n->prev=l;l->next=n;l->prev=h;h->next=l;}
#define list_first_entry_or_null(head,type,member) ((head)->next==(head)?NULL:(type *)((char *)(head)->next - offsetof(type,member)))
static void list_del(struct list_head *l){assert(l->next->prev==l && l->prev->next==l);l->next->prev=l->prev;l->prev->next=l->next;
 l->next=(void *)0xdead000000000100ULL;l->prev=(void *)0xdead000000000122ULL;}
'''
WRAPPER=r'''
static uint64_t canonical(uint64_t p){
 uint64_t start=(uintptr_t)pages;if(p>=start && p<start+sizeof(pages))return 0xfffffffe00050000ULL+p-start;return p;}
void host_reset(void){memset(pages,0xa5,sizeof(pages));memset(metadata,0xa5,sizeof(metadata));memset(metadata+16,0,8);}
void host_step(unsigned operation,unsigned index,unsigned locked,uint64_t *result,unsigned char *out){
 assert(index<8);memcpy(metadata+40,&locked,4);bug=0;pgtable_t value=NULL;
 if(!setjmp(trap)){if(operation)pgtable_trans_huge_deposit(&mm,&pmd,&pages[index]);else value=pgtable_trans_huge_withdraw(&mm,&pmd);}
 result[0]=canonical((uintptr_t)value);result[1]=bug;
 memcpy(out,metadata,64);uint64_t owner;memcpy(&owner,out+16,8);owner=canonical(owner);memcpy(out+16,&owner,8);
 memcpy(out+64,pages,sizeof(pages));for(unsigned i=0;i<8;i++)for(unsigned j=0;j<2;j++){
 uint64_t v;unsigned offset=64+i*64+8+j*8;memcpy(&v,out+offset,8);v=canonical(v);memcpy(out+offset,&v,8);}
}
'''


def run(args):
    from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE
    from unicorn.arm64_const import UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X2,UC_ARM64_REG_X30,UC_ARM64_REG_SP,UC_ARM64_REG_PC
    source=args.source.read_text()
    assert hashlib.sha256(args.source.read_bytes()).hexdigest()=='990748e9f12d796834dbe92a194454cbe2620d2664e5982ac2da0d35d2610935'
    functions=body(source,'void pgtable_trans_huge_deposit(')+'\n'+body(source,'pgtable_t pgtable_trans_huge_withdraw(')
    image=args.image.read_bytes();contracts=load('verify-stock-recovered-contracts.py')
    assert hashlib.sha256(image).hexdigest()==contracts.IMAGE_SHA and hashlib.sha256(args.symbols.read_bytes()).hexdigest()==contracts.SYMBOL_SHA
    kernel=load('stock-binary-evidence.py').Kernel(args.image,args.symbols);btf=kernel.btf;fields=load('test-dmabuf-stock-wrappers.py').btf_fields
    for name,required in {'page':{'lru':8},'ptdesc':{'pmd_huge_pte':16,'ptl':40}}.items():
        ident=next(i for i,t in enumerate(btf.types) if t['kind']==4 and t['name']==name)
        actual=fields(btf,ident)
        for member,offset in required.items():assert actual[member]==offset,(name,member)
    assert kernel.cfg['CONFIG_DEBUG_LIST']=='n' and kernel.cfg['CONFIG_LIST_HARDENED']=='y'
    assert kernel.cfg['CONFIG_ILLEGAL_POINTER_VALUE']=='0xdead000000000000'
    with tempfile.TemporaryDirectory(prefix='dmabuf-deposit-') as tmp:
        lib=Path(tmp)/'list.dylib';subprocess.run(['clang','-x','c','-std=c11','-Wall','-Wextra','-Werror','-dynamiclib','-o',str(lib),'-'],input=FIXTURE+functions+WRAPPER,text=True,check=True)
        host=ctypes.CDLL(str(lib));host.host_step.argtypes=[ctypes.c_uint]*3+[ctypes.c_void_p]*2
        uc=Uc(UC_ARCH_ARM64,UC_MODE_ARM);uc.mem_map(kernel.base,(len(image)+4095)&~4095);uc.mem_write(kernel.base,image)
        ram=0x1000000;uc.mem_map(ram,0x20000);stack=ram+0xf000;stop=ram+0x10000
        direct=0xffffff8001000000;uc.mem_map(direct,4096)
        metadata=0xfffffffe00040000;pages=0xfffffffe00050000;uc.mem_map(metadata,4096);uc.mem_map(pages,4096)
        state={}
        def hook(emu,address,size,user):
            if kernel.base<=address<kernel.base+len(image):
                word=struct.unpack_from('<I',image,address-kernel.base)[0]
                if word&0xffe0001f==0xd4200000:state['bug']=1;emu.emu_stop()
        uc.hook_add(UC_HOOK_CODE,hook);rng=random.Random(0x304d);steps=guards=0
        for case in range(300):
            host.host_reset();initial=bytearray(b'\xa5'*64);initial[16:24]=bytes(8)
            uc.mem_write(metadata,bytes(initial));uc.mem_write(pages,b'\xa5'*512)
            available=list(range(8));deposited=[]
            for step in range(24):
                operation=bool(available) and (not deposited or rng.choice((True,False)))
                index=available.pop() if operation else 0
                locked=0 if step==23 and case%3==0 else 1
                out=(ctypes.c_ubyte*576)();result=(ctypes.c_uint64*2)();host.host_step(operation,index,locked,result,out)
                uc.mem_write(metadata+40,struct.pack('<I',locked));state['bug']=0
                uc.reg_write(UC_ARM64_REG_X0,ram+0x1000);uc.reg_write(UC_ARM64_REG_X1,direct);uc.reg_write(UC_ARM64_REG_X2,pages+index*64)
                uc.reg_write(UC_ARM64_REG_X30,stop);uc.reg_write(UC_ARM64_REG_SP,stack)
                name='pgtable_trans_huge_deposit' if operation else 'pgtable_trans_huge_withdraw'
                uc.emu_start(kernel.address(name),stop,count=10000)
                assert state['bug']==result[1],('lock guard',case,step)
                assert state['bug'] or uc.reg_read(UC_ARM64_REG_PC)==stop,'instruction bound'
                if not operation and not state['bug']:assert uc.reg_read(UC_ARM64_REG_X0)==result[0],('withdraw return',case,step)
                actual=bytes(uc.mem_read(metadata,64))+bytes(uc.mem_read(pages,512))
                assert actual==bytes(out),('list/owner/poison bytes',case,step)
                if not state['bug']:
                    if operation:deposited.append(index)
                    else:
                        removed=(result[0]-pages)//64;assert removed in deposited;deposited.remove(removed);available.append(removed)
                elif operation:available.append(index)
                steps+=1;guards+=state['bug']
        print(f'PASS: {steps} stock ARM64 deposit/withdraw steps; exact ACK bodies, ownership/list/poison bytes, returns and {guards} held-lock guards')
        print('Valid list states only; corrupted-list debug callbacks, real lock ownership and SMP/lifetime remain unproven.')


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--image',type=Path,required=True);p.add_argument('--symbols',type=Path,required=True);p.add_argument('--source',type=Path,required=True);run(p.parse_args())
