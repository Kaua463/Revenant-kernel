#!/usr/bin/env python3
"""Integration move refusal/unlock + unchanged valid stock routing under sanitizers."""
from importlib.machinery import SourceFileLoader
from pathlib import Path
import subprocess
import tempfile

HERE=Path(__file__).resolve().parent
prepare=SourceFileLoader('dma_move_safety_prepare',str(HERE/'prepare-dmabuf-reimplementation.py')).load_module()
stock=SourceFileLoader('dma_move_safety_stock',str(HERE/'test-dmabuf-stock-move.py')).load_module()


def run():
    recipe=(HERE.parent/'tools/stock-recovery/dmabuf_huge_move.recovered.c').read_text()
    original=recipe.replace('move_dmabuf_huge_pmd(', 'stock_move(',1)
    main=r'''
static bool exercise(bool original,unsigned index,uint64_t old,unsigned locks,bool destination) {
 memset(entries,0,sizeof(entries));entries[1].val=old;
 entries[index].val=destination?0x600001:0;
 nr=bug=0;caps=0;mm.asid=0;mm.notifier=false;
 struct vm_area_struct v={&mm,locks&1?&file:NULL,locks&2?(void *)1:NULL};
 return original?stock_move(&v,0x400000,0x800000,entries+1,entries+index,true):
                 move_dmabuf_huge_pmd(&v,0x400000,0x800000,entries+1,entries+index,true);
}
int main(void) {
 const uint64_t old[]={0,0x200001,0x200003};
 for(unsigned different=0;different<2;different++)
  for(unsigned locks=0;locks<4;locks++)
   for(unsigned state=0;state<3;state++) {
    unsigned index=different?513:2;
    bool expected=exercise(true,index,old[state],locks,false);
    uint64_t saved[64][4];unsigned count=nr;memcpy(saved,rows,sizeof(saved));
    pmd_t saved_old=entries[1],saved_new=entries[index];
    bool actual=exercise(false,index,old[state],locks,false);
    assert(actual==expected && !bug && nr==count && !memcmp(rows,saved,nr*sizeof(rows[0])));
    assert(entries[1].val==saved_old.val && entries[index].val==saved_new.val);
    assert(!exercise(false,index,old[state],locks,true));
    assert(!bug && entries[1].val==old[state] && entries[index].val==0x600001);
    unsigned acquired=!!(locks&1)+!!(locks&2);
    assert(nr==2*acquired);
    for(unsigned i=0;i<acquired;i++)assert(rows[i][0]==1 && rows[nr-i-1][0]==2 && rows[i][1]==rows[nr-i-1][1]);
   }
 return 0;
}
'''
    with tempfile.TemporaryDirectory(prefix='dma-move-safety-') as temporary:
        binary=Path(temporary)/'test'
        subprocess.run(['clang','-x','c','-std=c11','-Wall','-Wextra','-Werror',
                        '-fsanitize=address,undefined','-fno-sanitize-recover=all','-o',str(binary),'-'],
                       input=stock.FIXTURE+original+prepare.integration_move(recipe)+main,text=True,check=True)
        subprocess.run([str(binary)],check=True)
    print('PASS: 24 valid move traces unchanged; 24 occupied destinations refuse without mutation and release rmap locks; helpers modeled, NOT MMU proof')


if __name__=='__main__':run()
