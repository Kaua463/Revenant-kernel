#!/usr/bin/env python3
"""Stock __split_vma routing/cleanup with modeled VMA allocation/tree/locks/adjust."""
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
static struct vm_area_struct old,new;static uint64_t rows[48][9];static unsigned nr;static uint64_t file_count;
static void trace(unsigned op,uint64_t a,uint64_t b,uint64_t c){uint64_t r[]={op,a,b,c,old.vm_start,old.vm_end,new.vm_start,new.vm_end,file_count};memcpy(rows[nr++],r,sizeof(r));}
static void vma_adjust_dmabuf_huge(struct vm_area_struct *v,uint64_t a,uint64_t b,long adj){(void)v;(void)adj;trace(8,0x1000000,a,b);}
static void vma_adjust_trans_huge(struct vm_area_struct *v,uint64_t a,uint64_t b,long adj){(void)v;(void)adj;trace(9,0x1000000,a,b);}
'''
WRAPPER=r'''
unsigned host_split(const uint64_t *in,uint64_t *out,uint64_t *trace_out){
 old=(struct vm_area_struct){0x400000,0x800000,in[0],0xabc,in[1]};memset(&new,0,sizeof(new));nr=0;file_count=17;
 unsigned below=in[2],fail=in[3];uint64_t addr=in[4];unsigned ret=0;
 if(in[6]>=2){trace(13,0x1000000,addr,0);if(in[6]==3){ret=0xfffffff0;goto done;}}
 trace(0,0x1000000,0,0);
 if(fail==1){ret=0xfffffff4;goto done;}
 new=old;if(below)new.vm_end=addr;else{new.vm_start=addr;new.vm_pgoff+=(addr-old.vm_start)>>12;}
 trace(1,0x1002000,0x1005000,0xcc0);
 if(fail==2){ret=0xfffffff4;goto free_new;}
 trace(2,0x1005000,0x1000000,0);
 if(fail==3){ret=0xffffffea;trace(3,0x1002000,0,0);goto free_new;}
 if(in[5])file_count++;
 if(in[6]>=2)trace(14,0x1005000,0,0);
 if(old.seq!=7){trace(5,0x1003000,0,0);old.seq=7;trace(6,0x1003000,0,0);}
 if(new.seq!=7){trace(5,0x1006000,0,0);new.seq=7;trace(6,0x1006000,0,0);}
 trace(7,0x1000000,0x1005000,0);dmabuf_huge_adjust_prepare(&old,old.vm_start,addr);
 if(below){old.vm_start=addr;old.vm_pgoff+=(addr-new.vm_start)>>12;}else old.vm_end=addr;
 trace(10,0x1000000,0x1005000,0);
 if(below)trace(11,0x1002000,UINT64_MAX,0);
 trace(12,0x1000000,0x1005000,addr);goto done;
 free_new:trace(4,0x1005000,0,0);
 done:out[0]=old.vm_start;out[1]=old.vm_end;out[2]=old.vm_pgoff;out[3]=old.seq;
 out[4]=new.vm_start;out[5]=new.vm_end;out[6]=new.vm_pgoff;out[7]=new.seq;out[8]=ret;out[9]=file_count;
 memcpy(trace_out,rows,nr*9*sizeof(uint64_t));return nr;
}
'''


def run(args):
    from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE
    from unicorn.arm64_const import (UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X2,UC_ARM64_REG_X3,UC_ARM64_REG_X30,UC_ARM64_REG_SP,UC_ARM64_REG_SP_EL0,UC_ARM64_REG_PC)
    image=args.image.read_bytes();contract=load('verify-stock-recovered-contracts.py')
    assert hashlib.sha256(image).hexdigest()==contract.IMAGE_SHA and hashlib.sha256(args.symbols.read_bytes()).hexdigest()==contract.SYMBOL_SHA
    kernel=load('stock-binary-evidence.py').Kernel(args.image,args.symbols);fields=load('test-dmabuf-stock-wrappers.py').btf_fields
    for name,required in {'vm_area_struct':{'vm_start':0,'vm_end':8,'vm_mm':16,'vm_flags':32,'vm_lock_seq':44,'vm_lock':48,'vm_pgoff':120,'vm_ops':112,'vm_file':128},'mm_struct':{'mm_lock_seq':224},'ma_state':{'index':8,'last':16,'node':24},'vma_prepare':{'vma':0,'insert':40},'vm_operations_struct':{'open':0,'close':8,'may_split':16},'file':{'f_count':24,'f_mapping':232}}.items():
        ident=next(i for i,t in enumerate(kernel.btf.types) if t['kind']==4 and t['name']==name);found=fields(kernel.btf,ident)
        for member,offset in required.items():assert found[member]==offset
    func=next(t for t in kernel.btf.types if t['kind']==12 and t['name']=='__split_vma');proto=kernel.btf.types[func['size']]
    assert len(proto['raw'])==8 and kernel.btf.types[proto['size']]['name']=='int'
    for i,name in enumerate(('vma_iterator','vm_area_struct','unsigned long','int')):
        typ=kernel.btf.types[proto['raw'][i*2+1]]
        if i<2:assert typ['kind']==2;typ=kernel.btf.types[typ['size']]
        assert typ['name']==name
    vmops_type=next(t for t in kernel.btf.types if t['kind']==4 and t['name']=='vm_operations_struct')
    for offset,result_name,arg_names in ((0,None,('vm_area_struct',)),(16,'int',('vm_area_struct','unsigned long'))):
        member=next(vmops_type['raw'][i+1] for i in range(0,len(vmops_type['raw']),3) if vmops_type['raw'][i+2]==offset*8)
        pointer=kernel.btf.types[member];assert pointer['kind']==2
        callback=kernel.btf.types[pointer['size']];assert callback['kind']==13 and len(callback['raw'])==2*len(arg_names)
        assert callback['size']==0 if result_name is None else kernel.btf.types[callback['size']]['name']==result_name
        for i,arg_name in enumerate(arg_names):
            typ=kernel.btf.types[callback['raw'][2*i+1]]
            if i==0:assert typ['kind']==2;typ=kernel.btf.types[typ['size']]
            assert typ['name']==arg_name
    code=FIXTURE+(Path(__file__).parents[1]/'tools/stock-recovery/dmabuf_huge_vma_hook.recovered.c').read_text()+WRAPPER
    with tempfile.TemporaryDirectory(prefix='dmabuf-split-vma-') as tmp:
        lib=Path(tmp)/'split.dylib';subprocess.run(['clang','-x','c','-std=c11','-Wall','-Wextra','-Werror','-dynamiclib','-o',str(lib),'-'],input=code,text=True,check=True)
        host=ctypes.CDLL(str(lib));host.host_split.argtypes=[ctypes.c_void_p]*3;host.host_split.restype=ctypes.c_uint
        uc=Uc(UC_ARCH_ARM64,UC_MODE_ARM);uc.mem_map(kernel.base,(len(image)+4095)&~4095);uc.mem_write(kernel.base,image)
        ram=0x1000000;uc.mem_map(ram,0x20000);vma=ram;mm=ram+0x1000;iterator=ram+0x2000;sem=ram+0x3000;task=ram+0x4000;new=ram+0x5000;newsem=ram+0x6000;stack=ram+0xf000;stop=ram+0x10000
        vmops=ram+0x7000;file=ram+0x8000;may=ram+0x11004;opened=ram+0x12004;closed=ram+0x13004
        # Exact CFI type tags checked by this stock caller before its BLR.
        uc.mem_write(may-4,struct.pack('<I',0xc839c7f3));uc.mem_write(opened-4,struct.pack('<I',0x6b80e497))
        names=('vm_area_dup','mas_preallocate','anon_vma_clone','mas_destroy','vm_area_free','down_write','up_write','vma_prepare','vma_adjust_dmabuf_huge','vma_adjust_trans_huge','vma_complete','mas_find','split_pad_vma')
        ops={kernel.address(name):i for i,name in enumerate(names)};ops.update({may:13,opened:14,closed:15});trace=[];state={};counts={i:0 for i in range(16)}
        def hook(emu,address,size,user):
            if address in ops:
                op=ops[address];x=[emu.reg_read(r) for r in (UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X2,UC_ARM64_REG_X3)];a,b,c=x[:3];result=0
                if op==0:assert a==vma;b=c=0
                elif op==1:assert [a,b,c]==[iterator,new,0xcc0]
                elif op==2:assert [a,b]==[new,vma];c=0
                elif op in (3,4,5,6):assert a==(iterator if op==3 else new if op==4 else sem if a==sem else newsem);b=c=0
                elif op in (7,10):a,b=struct.unpack('<Q',emu.mem_read(x[0],8))[0],struct.unpack('<Q',emu.mem_read(x[0]+40,8))[0];assert [a,b]==[vma,new];c=0
                elif op in (8,9):assert [a,b,c,x[3]]==[vma,0x400000,state['addr'],0]
                elif op==11:assert [a,b]==[iterator,(1<<64)-1];c=0
                elif op==12:assert x==[vma,new,state['addr'],state['below']]
                elif op==13:assert [a,b]==[vma,state['addr']];c=0;result=(1<<64)-16 if state['callbacks']==3 else 0
                elif op==14:assert a==new;b=c=0
                else:raise AssertionError('split must not call close')
                bounds=struct.unpack('<2Q',emu.mem_read(vma,16))+struct.unpack('<2Q',emu.mem_read(new,16));refcount=struct.unpack('<Q',emu.mem_read(file+24,8))[0];trace.append((op,a,b,c,*bounds,refcount))
                if op==0:
                    if state['fail']!=1:emu.mem_write(new,bytes(emu.mem_read(vma,208)));emu.mem_write(new+48,struct.pack('<Q',newsem));result=new
                elif op==1:result=1 if state['fail']==2 else 0
                elif op==2:result=(1<<64)-22 if state['fail']==3 else 0
                emu.reg_write(UC_ARM64_REG_X0,result);emu.reg_write(UC_ARM64_REG_PC,emu.reg_read(UC_ARM64_REG_X30))
            elif kernel.base<=address<kernel.base+len(image):
                word=struct.unpack_from('<I',image,address-kernel.base)[0]
                if word&0xffe0001f==0xd4200000:state['bug']=True;emu.emu_stop()
        uc.hook_add(UC_HOOK_CODE,hook);case=0
        def reset(flags,seq,addr,below,fail,has_file=0,callbacks=0):
            uc.mem_write(vma,bytes(208));uc.mem_write(vma,struct.pack('<5Q',0x400000,0x800000,mm,0,flags));uc.mem_write(vma+44,struct.pack('<I',seq));uc.mem_write(vma+48,struct.pack('<Q',sem));uc.mem_write(vma+120,struct.pack('<Q',0xabc));uc.mem_write(mm+224,struct.pack('<I',7));uc.mem_write(new,bytes(208));uc.mem_write(iterator,bytes(128));uc.mem_write(iterator+24,struct.pack('<Q',1))
            uc.mem_write(file,bytes(256));uc.mem_write(file+24,struct.pack('<Q',17));uc.mem_write(file+232,struct.pack('<Q',ram+0x9000))
            uc.mem_write(vmops,struct.pack('<3Q',opened if callbacks>=2 else 0,closed,may if callbacks>=2 else 0))
            uc.mem_write(vma+112,struct.pack('<Q',vmops if callbacks else 0));uc.mem_write(vma+128,struct.pack('<Q',file if has_file else 0))
            trace.clear();state.update(addr=addr,below=below,fail=fail,callbacks=callbacks,bug=False)
            for r,v in zip((UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X2,UC_ARM64_REG_X3),(iterator,vma,addr,below)):uc.reg_write(r,v)
            uc.reg_write(UC_ARM64_REG_X30,stop);uc.reg_write(UC_ARM64_REG_SP,stack);uc.reg_write(UC_ARM64_REG_SP_EL0,task)
        for dma in (0,1):
         for seq in (0,7,8):
          for below in (0,1):
           for fail in (0,1,2,3):
            for addr in (0x401000,0x600000,0x7ff000):
             for has_file in (0,1):
              for callbacks in (0,1,2,3):
                inputs=(ctypes.c_uint64*7)(dma<<39,seq,below,fail,addr,has_file,callbacks);out=(ctypes.c_uint64*10)();rows=(ctypes.c_uint64*(48*9))();n=host.host_split(inputs,out,rows);expected=[tuple(rows[i*9:(i+1)*9]) for i in range(n)]
                reset(dma<<39,seq,addr,below,fail,has_file,callbacks)
                try:uc.emu_start(kernel.address('__split_vma'),stop,count=100000)
                except Exception as error:raise RuntimeError(f'case={case} PC={uc.reg_read(UC_ARM64_REG_PC):#x} trace={trace}') from error
                assert not state['bug'] and uc.reg_read(UC_ARM64_REG_PC)==stop
                actual=[]
                for v in (vma,new):actual+=list(struct.unpack('<2Q',uc.mem_read(v,16)))+[struct.unpack('<Q',uc.mem_read(v+120,8))[0],struct.unpack('<I',uc.mem_read(v+44,4))[0]]
                actual.append(uc.reg_read(UC_ARM64_REG_X0)&0xffffffff)
                actual.append(struct.unpack('<Q',uc.mem_read(file+24,8))[0])
                assert actual==list(out),('state',case,actual,list(out));assert trace==expected,('order',case,trace,expected)
                for row in trace:counts[row[0]]+=1
                case+=1
        for addr in (0x3ff000,0x400000,0x800000,0x801000):
            reset(1<<39,7,addr,0,0);uc.emu_start(kernel.address('__split_vma'),stop,count=100000);assert state['bug'] and not trace
        # CFI mismatch must stop before the corresponding indirect callback.
        for entry,tag,callback_op,expected_refs in ((may,0xc839c7f3,13,17),(opened,0x6b80e497,14,18)):
            uc.mem_write(entry-4,struct.pack('<I',tag^1));reset(1<<39,7,0x600000,0,0,1,2)
            uc.emu_start(kernel.address('__split_vma'),stop,count=100000)
            assert state['bug'] and not any(row[0]==callback_op for row in trace)
            assert struct.unpack('<Q',uc.mem_read(file+24,8))[0]==expected_refs
            uc.mem_write(entry-4,struct.pack('<I',tag))
        assert all(counts[i] for i in range(15)) and counts[15]==0,counts
        print(f'PASS: {case} ARM64 split-VMA cases + 4 boundary BUG guards + 2 callback CFI guards; routes={counts}; old/new bounds/pgoff/seq, cleanup and pre-update adjust')
        print('may_split/open routing and inline get_file increment execute in stock; rejection and allocation/clone failures preserve count, no close. Callback bodies, VMA dup/free, anon clone, tree, locks and adjust modeled. No MMU or concurrent refcount/lifetime proof.')


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--image',type=Path,required=True);p.add_argument('--symbols',type=Path,required=True);run(p.parse_args())
