#!/usr/bin/env python3
"""PTE remap branch against actual ARM64; bulk/allocator/locking helpers modeled."""
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


PTE_FIXTURE=r'''
static pte_t ptes[4096];static unsigned maps;
static uint64_t pte_address(pte_t *p){return 0xffffff8002000000ULL+(p-ptes)*8;}
static pte_t *pte_alloc_map_lock(struct mm_struct *m,pmd_t *p,unsigned long a,spinlock_t **l){
 unsigned index=(unsigned)(p-pmds);assert(index<8);
 if(!p->val){trace(10,0x1001000,pmd_address(p),0,0);if(fail==2)return NULL;p->val=(0x2000000ULL+index*4096)|3;}
 trace(11,0x1001000,pmd_address(p),a,0);
 if(++maps==fail-2)return NULL;
 *l=(void *)0xfffffffe00080028ULL;(void)m;return ptes+index*512+((a>>12)&511);
}
static void set_ptes(struct mm_struct *m,unsigned long a,pte_t *p,pte_t v,unsigned n){
 (void)m;if(n==1){*p=v;if((v.val&0x40000000000041ULL)==0x40000000000001ULL){trace(13,0xd5033a9f,0,0,0);trace(13,0xd5033fdf,0,0,0);}}
 else {trace(12,0x1001000,a,pte_address(p),v.val);trace(15,n,0,0,0);for(unsigned i=0;i<n;i++)p[i].val=v.val+(uint64_t)i*4096;}
}
static void pte_unmap_unlock(pte_t *p,spinlock_t *l){(void)p;spin_unlock(l);trace(14,0,0,0,0);}
'''

WRAPPER=r'''
unsigned host_remap(const uint64_t *in,uint64_t *out,uint64_t *trace_out) {
 struct vm_area_struct v={in[0],in[1],in[2],0xaabb,(unsigned)in[3],&mm};
 mm.seq=7;mm.count=in[4];mm.pgd.val=in[5];counter=0;other=in[6];fail=in[7];nr=maps=allocs=bug=0;
 memset(pmds,0,sizeof(pmds));memset(ptes,0,sizeof(ptes));
 if(in[13])for(unsigned i=0;i<8;i++)pmds[i].val=(0x2000000ULL+i*4096)|3;
 if(in[14])ptes[(in[8]>>12)&4095].val=1;
 int ret=0;if(!setjmp(trap))ret=dmabuf_huge_remap_pfn_range(&v,in[8],in[9],in[10],(pgprot_t){in[11]},(unsigned)in[12]);
 out[0]=(uint32_t)ret;out[1]=v.vm_flags;out[2]=v.vm_pgoff;out[3]=v.seq;out[4]=mm.count;out[5]=other;out[6]=mm.pgd.val;out[7]=bug;
 memcpy(out+8,pmds,sizeof(pmds));memcpy(out+520,ptes,sizeof(ptes));memcpy(trace_out,rows,nr*5*sizeof(uint64_t));return nr;
}
'''


def run(args):
    from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE
    from unicorn.arm64_const import (UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X2,UC_ARM64_REG_X3,UC_ARM64_REG_X4,UC_ARM64_REG_X30,UC_ARM64_REG_X5,UC_ARM64_REG_SP,UC_ARM64_REG_SP_EL0,UC_ARM64_REG_PC)
    base=load('test-dmabuf-stock-remap-pmd.py');image=args.image.read_bytes();contract=load('verify-stock-recovered-contracts.py')
    assert hashlib.sha256(image).hexdigest()==contract.IMAGE_SHA
    assert hashlib.sha256(args.symbols.read_bytes()).hexdigest()==contract.SYMBOL_SHA
    kernel=load('stock-binary-evidence.py').Kernel(args.image,args.symbols)
    base.verify_btf(kernel)
    marker='/* Explicitly unsupported in this PMD-only fixture, not production stubs. */'
    assert base.FIXTURE.count(marker)==1
    fixture=base.FIXTURE.split(marker)[0]+PTE_FIXTURE
    code=fixture+(Path(__file__).parents[1]/'tools/stock-recovery/dmabuf_huge_remap.recovered.c').read_text()+WRAPPER
    with tempfile.TemporaryDirectory(prefix='dmabuf-remap-pte-') as tmp:
        lib=Path(tmp)/'remap.dylib';subprocess.run(['clang','-x','c','-std=c11','-Wall','-Wextra','-Werror','-dynamiclib','-o',str(lib),'-'],input=code,text=True,check=True)
        host=ctypes.CDLL(str(lib));host.host_remap.argtypes=[ctypes.c_void_p]*3;host.host_remap.restype=ctypes.c_uint
        uc=Uc(UC_ARCH_ARM64,UC_MODE_ARM);uc.mem_map(kernel.base,(len(image)+4095)&~4095);uc.mem_write(kernel.base,image)
        ram=0x1000000;uc.mem_map(ram,0x20000);vma,mm,pgd,task,lock,stack,stop=[ram+x for x in (0,0x1000,0x2000,0x4000,0x6000,0xf000,0x10000)]
        direct=0xffffff8001000000;pte_base=0xffffff8002000000
        uc.mem_map(direct,4096);uc.mem_map(pte_base,32768)
        counter=kernel.address('dmabuf_hugetlb_contpte_map');assert kernel.span('dmabuf_hugetlb_contpte_map') is None
        uc.mem_map(counter&~4095,4096);uc.mem_write(kernel.address('memstart_addr'),bytes(8))
        assert kernel.symbols['system_cpucaps'][0][1]=='B' and kernel.span('system_cpucaps') is None
        uc.mem_map(kernel.address('system_cpucaps')&~4095,4096)
        ops={'down_write':1,'up_write':2,'__pmd_alloc':3,'__pte_alloc':10,'__pte_offset_map_lock':11,'contpte_set_ptes':12,'_raw_spin_unlock':9,'__rcu_read_unlock':14}
        funcs={kernel.address(n):op for n,op in ops.items()};trace=[];state={}
        def hook(emu,address,size,user):
            if address in funcs:
                op=funcs[address];x=[emu.reg_read(r) for r in (UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X2,UC_ARM64_REG_X3,UC_ARM64_REG_X4)]
                count={1:1,2:1,3:3,10:2,11:3,12:4,9:1,14:0}[op]
                trace.append((op,*[x[i] if i<count else 0 for i in range(4)]));result=0
                if op==3:
                    result=(1<<64)-12 if state['fail']==1 else 0
                    if not result:emu.mem_write(pgd,struct.pack('<Q',0x1000003))
                elif op==10:
                    result=(1<<64)-12 if state['fail']==2 else 0
                    if not result:emu.mem_write(x[1],struct.pack('<Q',(0x2000000+((x[1]-direct)//8)*4096)|3))
                elif op==11:
                    state['maps']+=1
                    if state['maps']!=state['fail']-2:
                        result=pte_base+((x[1]-direct)//8)*4096+((x[2]>>12)&511)*8
                        emu.mem_write(x[3],struct.pack('<Q',0xfffffffe00080028))
                elif op==12:
                    trace.append((15,x[4]&0xffffffff,0,0,0))
                    for i in range(x[4]&0xffffffff):emu.mem_write(x[2]+i*8,struct.pack('<Q',(x[3]+i*4096)&((1<<64)-1)))
                emu.reg_write(UC_ARM64_REG_X0,result);emu.reg_write(UC_ARM64_REG_PC,emu.reg_read(UC_ARM64_REG_X30))
            elif kernel.base<=address<kernel.base+len(image):
                word=struct.unpack_from('<I',image,address-kernel.base)[0]
                if word&0xffe0001f==0xd4200000:state['bug']=1;emu.emu_stop()
                elif word in (0xd5033a9f,0xd5033fdf):trace.append((13,word,0,0,0))
        uc.hook_add(UC_HOOK_CODE,hook)
        coverage={'multi_success':0,'partial_failure':0,'cow_reject':0,'bug':0,'single_pte':0,'bulk_pte':0}
        for case in range(360):
            address=(1<<21)+(4096 if case%3 else 0);size=(1,4096,1<<21,(1<<21)+4096,3<<21,0)[case%6]
            if case%19==0:address+=1
            end=address+((size+4095)&~4095);flags=(0,32,40,1<<39)[case%4]
            values=(address,end+(4096 if case%11==0 else 0),flags,case%8,(0,(1<<64)-1)[case%2],(0,0x1000003)[case%2],(0,(1<<64)-1)[case%2],(case//6)%6,address,0x4000,size,
                    3|((case&1)<<54)|(((case>>1)&1)<<6)|(((case>>2)&1)<<52)|(((case>>3)&1)<<56),(1,2,0xffffffff)[case%3],case%2,int(case%17==0))
            inputs=(ctypes.c_uint64*15)(*values);out=(ctypes.c_uint64*4616)();rows=(ctypes.c_uint64*640)()
            n=host.host_remap(inputs,out,rows);expected=[tuple(rows[i*5:(i+1)*5]) for i in range(n)]
            uc.mem_write(vma,struct.pack('<5Q',values[0],values[1],mm,0,flags));uc.mem_write(vma+44,struct.pack('<I',values[3]));uc.mem_write(vma+48,struct.pack('<Q',lock));uc.mem_write(vma+120,struct.pack('<Q',0xaabb))
            for a,v in ((mm+112,pgd),(mm+128,values[4]),(pgd,values[5]),(counter,values[6])):uc.mem_write(a,struct.pack('<Q',v))
            uc.mem_write(mm+224,struct.pack('<I',7));uc.mem_write(direct,bytes(4096));uc.mem_write(pte_base,bytes(32768))
            if values[13]:
                for i in range(8):uc.mem_write(direct+i*8,struct.pack('<Q',(0x2000000+i*4096)|3))
            if values[14]:uc.mem_write(pte_base+((address>>12)&4095)*8,struct.pack('<Q',1))
            trace.clear();state.update(fail=values[7],maps=0,bug=0)
            for r,v in zip((UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X2,UC_ARM64_REG_X3,UC_ARM64_REG_X4,UC_ARM64_REG_X5),(vma,address,values[9],size,values[11],values[12])):uc.reg_write(r,v)
            uc.reg_write(UC_ARM64_REG_X30,stop);uc.reg_write(UC_ARM64_REG_SP,stack);uc.reg_write(UC_ARM64_REG_SP_EL0,task)
            try:
                uc.emu_start(kernel.address('dmabuf_huge_remap_pfn_range'),stop,count=100000)
            except Exception as error:
                raise RuntimeError(f'case={case} PC={uc.reg_read(UC_ARM64_REG_PC):#x} trace={trace}') from error
            assert state['bug'] or uc.reg_read(UC_ARM64_REG_PC)==stop,'instruction bound'
            actual=[0 if state['bug'] else uc.reg_read(UC_ARM64_REG_X0)&0xffffffff]
            actual.extend(struct.unpack('<Q',uc.mem_read(a,8))[0] for a in (vma+32,vma+120));actual.append(struct.unpack('<I',uc.mem_read(vma+44,4))[0])
            actual.extend(struct.unpack('<Q',uc.mem_read(a,8))[0] for a in (mm+128,counter,pgd));actual.append(state['bug'])
            assert actual==list(out[:8]),('outputs',case,actual,list(out[:8]))
            assert bytes(uc.mem_read(direct,4096))==bytes(out)[64:4160],('PMDs',case)
            assert bytes(uc.mem_read(pte_base,32768))==bytes(out)[4160:],('PTEs',case)
            assert trace==expected,('trace',case,trace,expected)
            mapped=(out[5]-values[6])&((1<<64)-1)
            coverage['multi_success']+=out[0]==0 and not out[7] and mapped>1
            coverage['partial_failure']+=out[0]==0xfffffff4 and mapped>0
            coverage['cow_reject']+=out[0]==0xffffffea
            coverage['bug']+=bool(out[7])
            coverage['bulk_pte']+=any(row[0]==12 for row in trace)
            coverage['single_pte']+=mapped>0 and not any(row[0]==12 for row in trace)
        assert all(coverage.values()),coverage
        print('PASS: 360 exact-stock ARM64 PTE-remap cases; output bytes, special/CONT masks, first-PTE guards, partial failures, counters and trace')
        print(f'Coverage categories: {coverage}')
        print('Bulk contiguous-PTE/allocator/locking helpers modeled; not their implementation, SMP, MMU or lifetime proof.')


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--image',type=Path,required=True);p.add_argument('--symbols',type=Path,required=True);run(p.parse_args())
