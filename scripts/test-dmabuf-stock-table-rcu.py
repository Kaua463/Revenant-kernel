#!/usr/bin/env python3
"""Stock page-table batching/RCU bodies; modeled allocator, TLB and grace period."""
import argparse
import hashlib
from importlib.machinery import SourceFileLoader
from pathlib import Path
import struct


def load(name):
    return SourceFileLoader(name, str(Path(__file__).with_name(name))).load_module()


def run(args):
    from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE
    from unicorn.arm64_const import (UC_ARM64_REG_X0, UC_ARM64_REG_X1,
                                    UC_ARM64_REG_X2, UC_ARM64_REG_X30,
                                    UC_ARM64_REG_PC, UC_ARM64_REG_SP)
    contract=load('verify-stock-recovered-contracts.py');image=args.image.read_bytes()
    assert hashlib.sha256(image).hexdigest()==contract.IMAGE_SHA
    assert hashlib.sha256(args.symbols.read_bytes()).hexdigest()==contract.SYMBOL_SHA
    k=load('stock-binary-evidence.py').Kernel(args.image,args.symbols)
    for option in ('CONFIG_MMU_GATHER_TABLE_FREE','CONFIG_MMU_GATHER_RCU_TABLE_FREE','CONFIG_ARM64_4K_PAGES'):
        assert k.cfg[option]=='y'
    btf=k.btf;fields=load('test-dmabuf-stock-wrappers.py').btf_fields
    for name,size,required in (('mmu_gather',128,{'batch':8,'local':48,'active':40}),
                               ('mmu_table_batch',24,{'rcu':0,'nr':16,'tables':24})):
        ident=next(i for i,t in enumerate(btf.types) if t['kind']==4 and t['name']==name)
        assert btf.types[ident]['size']==size
        found=fields(btf,ident)
        for member,offset in required.items():assert found[member]==offset
    for name in ('tlb_remove_table','tlb_flush_mmu','tlb_remove_table_rcu'):
        proto=btf.types[next(t for t in btf.types if t['kind']==12 and t['name']==name)['size']]
        assert proto['size']==0 and len(proto['raw'])==(4 if name=='tlb_remove_table' else 2)
    source=args.source.read_bytes()
    assert hashlib.sha256(source).hexdigest()=='129bfb331764a879f2f2ad3ec9776f4fc813e16b2e256b6c62f26e9091ec58ea'
    uc=Uc(UC_ARCH_ARM64,UC_MODE_ARM);uc.mem_map(k.base,(len(image)+4095)&~4095);uc.mem_write(k.base,image)
    ram=0x2000000;uc.mem_map(ram,0x40000);tlb=ram;stack=ram+0xf000;stop=ram+0x10000;batch_base=ram+0x20000
    funcs={k.address(n):op for n,op in (('__get_free_pages',1),('call_rcu',2),('free_page_and_swap_cache',3),('free_pages',4),('smp_call_function',5))}
    flush=0xffffffc08033cafc
    assert any(line.split()[-1]=='tlb_flush_mmu_tlbonly' and int(line.split()[0],16)==flush for line in args.symbols.read_text().splitlines())
    funcs[flush]=6
    forbidden={k.address('free_pages_and_swap_cache'),k.address('__free_pages')}
    state={};trace=[]

    def hook(emu,address,size,user):
        assert address not in forbidden,'unexpected backing-page/free helper'
        if address in funcs:
            op=funcs[address];x=[emu.reg_read(r) for r in (UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X2)]
            trace.append((op,*x[:{1:2,2:2,3:1,4:2,5:3,6:1}[op]]));result=0
            if op==1:
                assert x[:2]==[0x2800,0]
                if not state['alloc_fail']:
                    result=batch_base+state['allocs']*4096;state['allocs']+=1
                    assert state['allocs']<16;emu.mem_write(result,b'\xa5'*4096)
            elif op==2:
                assert x[1]==k.address('tlb_remove_table_rcu') and x[0] not in state['callbacks']
                state['callbacks'].append(x[0])
                nr=struct.unpack('<I',emu.mem_read(x[0]+16,4))[0];assert 0<nr<=509
                state['pending'].extend(struct.unpack('<'+str(nr)+'Q',emu.mem_read(x[0]+24,nr*8)))
            elif op==3:
                assert x[0] not in state['freed'],'table freed twice'
                if state['alloc_fail']:assert state['synchronized'],'fallback free before SMP synchronization'
                else:assert state['callback_running'] and x[0] in state['pending'],'free before modeled RCU callback'
                state['freed'].add(x[0])
            elif op==4:
                assert state['callback_running'] and x[1]==0 and x[0] not in state['batch_freed']
                state['batch_freed'].add(x[0])
            elif op==5:
                assert state['alloc_fail'] and x==[k.address('tlb_remove_table_smp_sync'),0,1]
                assert trace[-2]==(6,tlb),'fallback requires flush before SMP sync'
                state['synchronized']=True
            else:assert x[0]==tlb
            emu.reg_write(UC_ARM64_REG_X0,result);emu.reg_write(UC_ARM64_REG_PC,emu.reg_read(UC_ARM64_REG_X30))
        elif k.base<=address<k.base+len(image):
            word=struct.unpack_from('<I',image,address-k.base)[0]
            assert word&0xffe0001f!=0xd4200000,('stock BUG',hex(address))
    uc.hook_add(UC_HOOK_CODE,hook)

    def call(name,*values):
        for reg,value in zip((UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X2),values):uc.reg_write(reg,value)
        uc.reg_write(UC_ARM64_REG_X30,stop);uc.reg_write(UC_ARM64_REG_SP,stack)
        uc.emu_start(k.address(name),stop,count=100000)
        assert uc.reg_read(UC_ARM64_REG_PC)==stop,('instruction bound',name)

    cases=total_tables=total_callbacks=0
    for fail in (False,True):
      for count in (0,1,2,508,509,510,1018,1019):
        uc.mem_write(tlb,bytes(128));trace.clear()
        state.update(alloc_fail=fail,allocs=0,callbacks=[],pending=[],freed=set(),batch_freed=set(),callback_running=False,synchronized=False)
        tables=[0xfffffffe01000000+i*64 for i in range(count)]
        for i,table in enumerate(tables):
            before=len(trace);state['synchronized']=False;call('tlb_remove_table',tlb,table)
            batch=struct.unpack('<Q',uc.mem_read(tlb+8,8))[0]
            if fail:
                assert trace[before:]==[(1,0x2800,0),(6,tlb),(5,k.address('tlb_remove_table_smp_sync'),0,1),(3,table)]
                assert not batch and state['freed']==set(tables[:i+1])
            else:
                expected_nr=(i+1)%509
                assert bool(batch)==bool(expected_nr)
                if batch:
                    assert struct.unpack('<I',uc.mem_read(batch+16,4))[0]==expected_nr
                    assert struct.unpack('<'+str(expected_nr)+'Q',uc.mem_read(batch+24,expected_nr*8))==tuple(tables[i+1-expected_nr:i+1])
                assert not state['freed'],'normal queueing cannot free before RCU'
                assert len(state['callbacks'])==(i+1)//509
        call('tlb_flush_mmu',tlb)
        assert not struct.unpack('<Q',uc.mem_read(tlb+8,8))[0]
        assert struct.unpack('<Q',uc.mem_read(tlb+40,8))[0]==tlb+48
        expected_callbacks=0 if fail else (count+508)//509
        assert len(state['callbacks'])==expected_callbacks
        if not fail:
            assert state['pending']==tables and not state['freed']
            for callback in state['callbacks']:
                state['callback_running']=True;before=len(trace);call('tlb_remove_table_rcu',callback)
                nr=struct.unpack('<I',uc.mem_read(callback+16,4))[0]
                wanted=struct.unpack('<'+str(nr)+'Q',uc.mem_read(callback+24,nr*8))
                assert trace[before:]==[(3,table) for table in wanted]+[(4,callback,0)]
                state['callback_running']=False
            assert state['batch_freed']==set(state['callbacks'])
        assert state['freed']==set(tables)
        before=len(trace);call('tlb_flush_mmu',tlb)
        assert trace[before:]==[(6,tlb)],'empty repeated flush cannot enqueue/free again'
        cases+=1;total_tables+=count;total_callbacks+=expected_callbacks
    print(f'PASS: {cases} stock batching/fallback/RCU chains; {total_tables} table releases and {total_callbacks} callbacks; 509-table boundaries, flush-before-sync, delayed-free and exactly-once checks')
    print('Actual stock queue/flush/callback instructions; independent scoped oracle. Allocator, TLB flush, SMP sync and RCU grace period modeled. Not live MMU, SMP/lifetime or integration proof.')


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('image','symbols','source'):p.add_argument('--'+name,type=Path,required=True)
    run(p.parse_args())
