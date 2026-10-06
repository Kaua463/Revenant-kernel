#!/usr/bin/env python3
"""Exact trace transforms, disabled byte-equivalence and real move-body event routing."""
from importlib.machinery import SourceFileLoader
from pathlib import Path
import subprocess
import tempfile
import unittest

HERE=Path(__file__).resolve().parent
module=SourceFileLoader('dma_runtime_trace',str(HERE/'prepare-dmabuf-runtime-trace.py')).load_module()
fault_test=SourceFileLoader('dma_runtime_trace_input',str(HERE/'test-dmabuf-fault-sites.py')).load_module()
move=SourceFileLoader('dma_runtime_trace_move',str(HERE/'test-dmabuf-stock-move.py')).load_module()


class Trace(unittest.TestCase):
    def setUp(self):
        self.input=module.sites.transform(fault_test.current_candidate())

    def test_trace_scope_and_exact_reverse(self):
        before=self.input.decode();after=module.transform(self.input).decode()
        for signature,anchor,event in module.EVENTS:
            body=module.extract(before,signature)
            marker='\n#ifdef CONFIG_XIAOMI_DMABUF_RUNTIME_AUDIT\n\tpr_info("'+event+'\\n");\n#endif'
            expected=body.replace(anchor,anchor+marker,1)
            self.assertIn(expected,after)
            after=after.replace(marker,'',1)
        self.assertEqual(after,before)

    def test_drift_uninstrumented_and_repeat_rejected(self):
        for data in (self.input+b'\n',fault_test.current_candidate(),module.transform(self.input)):
            with self.assertRaises(ValueError):module.transform(data)

    def test_successful_move_body_emits_only_when_enabled_and_moved(self):
        body=module.extract(module.transform(self.input).decode(),'bool move_dmabuf_huge_pmd(')
        fixture=move.FIXTURE+r'''
static unsigned events;
#ifdef CONFIG_XIAOMI_DMABUF_RUNTIME_AUDIT
static void pr_info(const char *format){assert(!strcmp(format,"DMA_AUDIT_HUGE_MOVE\n"));events++;}
#endif
'''
        main=r'''
int main(void){
 (void)trap;bug=0;
 for(unsigned valid=0;valid<2;valid++)for(unsigned occupied=0;occupied<2;occupied++){
  memset(entries,0,sizeof(entries));entries[1].val=valid?0x200001:0;entries[513].val=occupied?0x600001:0;
  nr=events=0;caps=0;mm.asid=0;mm.notifier=false;
  struct vm_area_struct v={&mm,&file,0};
  bool result=move_dmabuf_huge_pmd(&v,0x400000,0x800000,entries+1,entries+513,false);
  assert(result==(valid&&!occupied) && !bug);
#ifdef CONFIG_XIAOMI_DMABUF_RUNTIME_AUDIT
  assert(events==result);
#else
  assert(events==0);
#endif
 }
 return 0;
}
'''
        with tempfile.TemporaryDirectory(prefix='dma-trace-native-') as temporary:
            for enabled in (False,True):
                binary=Path(temporary)/str(enabled)
                command=['clang','-x','c','-std=c11','-Wall','-Wextra','-Werror',
                         '-fsanitize=address,undefined','-o',str(binary),'-']
                if enabled:command.append('-DCONFIG_XIAOMI_DMABUF_RUNTIME_AUDIT=1')
                subprocess.run(command,input=fixture+body+main,text=True,check=True)
                subprocess.run([str(binary)],check=True)


if __name__=='__main__':unittest.main()
