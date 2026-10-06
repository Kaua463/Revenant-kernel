#!/usr/bin/env python3
"""Review-overlay gates: exact inputs, scoped hooks, disabled path and round-trip."""
import argparse
from importlib.machinery import SourceFileLoader
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

mod=SourceFileLoader('prepare_dma',str(Path(__file__).with_name('prepare-dmabuf-reimplementation.py'))).load_module()
ARGS=None


def disabled(text):
    """Remove only our exact feature blocks; keep upstream preprocessor verbatim."""
    lines=text.splitlines(keepends=True);result=[];depth=0;keep=False
    for line in lines:
        stripped=line.strip()
        if not depth:
            if stripped=='#ifdef CONFIG_XIAOMI_DMABUF_HUGETLB':depth=1;keep=False
            elif line!='#include <linux/xiaomi_dmabuf_huge.h>\n':result.append(line)
        else:
            if stripped.startswith(('#if ','#ifdef ','#ifndef ')):depth+=1
            elif stripped.startswith('#endif'):
                depth-=1
                if not depth:continue
            elif stripped=='#else' and depth==1:keep=True;continue
            if keep:result.append(line)
    if depth:raise ValueError('unclosed feature block')
    return ''.join(result)


class Overlay(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source={name:(ARGS.source/name).read_text() for name in mod.SOURCES}
        folder=Path(__file__).parents[1]/'tools/stock-recovery'
        cls.recipes={name:(folder/('dmabuf_huge_'+name+'.recovered.c')).read_text() for name in mod.RECIPES}
        cls.result=mod.candidate(cls.source,cls.recipes)

    def test_disabled_mm_identical(self):
        for name in ('mm/memory.c','mm/mmap.c','mm/mremap.c','mm/huge_memory.c'):
            # Appended core has one separating newline; no upstream edit.
            self.assertEqual(disabled(self.result[name]).rstrip('\n'),self.source[name].rstrip('\n'),name)

    def test_preserve_generic_merge_and_brk(self):
        text=self.result['mm/mmap.c']
        self.assertEqual(text.count('vma_adjust_trans_huge(vma, vma_start, vma_end, adj_start);'),1)
        self.assertEqual(text.count('vma_adjust_trans_huge(vma, vma->vm_start, addr + len, 0);'),1)
        self.assertEqual(text.count('dmabuf_huge_adjust_prepare('),3)

    def test_exact_recipes_and_build_gate(self):
        text=self.result['mm/huge_memory.c']
        for name in ('zap','split','wrappers','range','move','remap'):
            self.assertIn(self.recipes[name],text)
        self.assertIn('CONFIG_PGTABLE_LEVELS != 3 || !USE_SPLIT_PMD_PTLOCKS',text)
        self.assertIn('\tdefault n\n',self.result['mm/Kconfig'])
        self.assertEqual(self.result['mm/Makefile'],self.source['mm/Makefile'])
        self.assertNotIn('EXPORT_SYMBOL',text[len(self.source['mm/huge_memory.c']):])

    def test_nonunique_anchor_rejected(self):
        source=dict(self.source);source['mm/mmap.c']+='\tvma_adjust_trans_huge(vma, start, end, 0);'
        with self.assertRaisesRegex(ValueError,'anchor'):mod.candidate(source,self.recipes)

    def test_patch_forward_reverse_and_drift(self):
        with tempfile.TemporaryDirectory(prefix='dmabuf-overlay-') as temp:
            temp=Path(temp);output=temp/'out';repo=temp/'reference'
            mod.run(argparse.Namespace(source=ARGS.source,image=ARGS.image,symbols=ARGS.symbols,output=output))
            shutil.copytree(ARGS.source,repo)
            patch=str(output/'dmabuf-review.patch')
            subprocess.run(['git','apply','--check',patch],cwd=repo,check=True,capture_output=True)
            subprocess.run(['git','apply',patch],cwd=repo,check=True,capture_output=True)
            for name,text in self.result.items():self.assertEqual((repo/name).read_text(),text,name)
            subprocess.run(['git','apply','--reverse','--check',patch],cwd=repo,check=True,capture_output=True)
            subprocess.run(['git','apply','--reverse',patch],cwd=repo,check=True,capture_output=True)
            for name,text in self.source.items():self.assertEqual((repo/name).read_text(),text,name)
            self.assertFalse((repo/'include/linux/xiaomi_dmabuf_huge.h').exists())
            (repo/'mm/mmap.c').write_text(self.source['mm/mmap.c']+'/* drift */\n')
            bad_output=temp/'bad-out'
            with self.assertRaisesRegex(ValueError,'input drift'):
                mod.run(argparse.Namespace(source=repo,image=ARGS.image,symbols=ARGS.symbols,output=bad_output))
            self.assertFalse(bad_output.exists(),'fail closed before any output')
            with self.assertRaisesRegex(ValueError,'must not exist'):
                mod.run(argparse.Namespace(source=ARGS.source,image=ARGS.image,symbols=ARGS.symbols,output=output))


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('source','image','symbols'):p.add_argument('--'+name,type=Path,required=True)
    ARGS=p.parse_args();unittest.main(argv=[__file__])
