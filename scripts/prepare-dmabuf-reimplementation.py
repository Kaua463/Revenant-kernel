#!/usr/bin/env python3
"""Generate a review-only, pinned ACK DMA overlay; never edits a live checkout."""
import argparse
import difflib
import hashlib
from importlib.machinery import SourceFileLoader
import json
from pathlib import Path

COMMIT='f7ebe251035c0d15ff90c6a0a320697932785fad'
SOURCES={
 'mm/mmap.c':'1e554a480b57fed37600bc36ff3cab66c164af29934ff88362e1ed4bb6e73e5e',
 'mm/mremap.c':'0613e0605fd73f89fe2b8040e64f8293a8619b64d84a33cbb321f8dfc113ab7b',
 'mm/Kconfig':'2a53d16cfe662c2f2ce425faa3cd9c1fb09e5071e570f7ebd0ab9b314c7e5e4a',
 'mm/Makefile':'2d0a7c3900d0332a3069c8f201095bc3f6d142ab03d9c95bf23a6ea522479ed3',
 'include/linux/huge_mm.h':'7424c9a89ff80e4435b3943b2a282c23b2e4445554682f87519607a7454308fe',
 'include/linux/mm.h':'36ca8de78bcc1d76141df2e7e60654002086170305c19784072d1ec5b9323f25',
 'include/linux/mm_types.h':'83217ab94bccfca029b38c6a503a4f6ae581d981a4afd60ffc0423a6cd5e8c4b',
 'include/linux/pgtable.h':'bdfc3c9f86b18719f0bec51cfb5174918a81285da4eefefe9afd3880fac164fc',
 'arch/arm64/include/asm/pgtable.h':'e1f09d4c505f326c18dc93ca18a132978232245b0bb0ea3669404f6cf52f5d61',
 'mm/memory.c':'7cd250cb365f15977d74bb9283f9c0a8399c3c8dcd281b54aaeb1a987ce894cb',
 'mm/huge_memory.c':'21500d58bf839040cd8caaa053f1004983f3d8cdbb64503ddbd54bd6b0cedf3a',
}
RECIPES={
 'zap':'e9729739827c51eabb21323b16efdcc745aa7a1191c0efb5d8943ccc98a95938',
 'split':'5dff89e30e137957427eeab75f1862e5626551436e6873e4dd21fea381886951',
 'wrappers':'b49497af15be2f8527cee677aa59e21c7863a01e557d942180a35b7bcd0d151c',
 'range':'7249d2e0471acbedf30c91d5e5c061a0271ac6910a12ee839c7134c7689e6b8a',
 'move':'eeb3d3a182ded7947049c8ee025b1ba88c6c51d19dc9440c5b9b6aa18c5e83bc',
 'remap':'b14df72dfc60a08e119f55eeea6859a1343522a1c693729e506ff80eb20f1456',
 'hooks':'9508bea66db25c1476cd956520b9ce0dfd76a2451acf36ba0398f6012e896825',
 'unmap_hook':'ce75f93c05a468fa54ab7887038729c6471755b4ba24c71d60633f55632952ca',
 'move_hook':'2333aecb3220c1fa1c50fbada7c16481600a62ff42ea2562071f73d2c9d26801',
 'vma_hook':'352ce11903cd9418af2e5320d33df0da30f86894c29a17abbc4ee4664054c2bd',
}
HEADER='''/* SPDX-License-Identifier: GPL-2.0-only */
/* Exact rodin stock contract; review-only until integration gates pass. */
#ifndef _LINUX_XIAOMI_DMABUF_HUGE_H
#define _LINUX_XIAOMI_DMABUF_HUGE_H
#include <linux/mm.h>
#include <linux/huge_mm.h>

#ifdef CONFIG_XIAOMI_DMABUF_HUGETLB
/* Recovered bit; original Xiaomi macro spelling is not established. */
#define VM_XIAOMI_DMABUF_HUGE (1UL << 39)
struct mmu_gather;
spinlock_t *__pmd_dmabuf_huge_lock(pmd_t *, struct vm_area_struct *);
int zap_dmabuf_huge_pmd(struct mmu_gather *, struct vm_area_struct *, pmd_t *, unsigned long);
void __split_dmabuf_huge_pmd(struct vm_area_struct *, pmd_t *, unsigned long, bool, struct folio *);
void zap_split_dmabuf_huge_pmd(struct vm_area_struct *, pmd_t *, unsigned long, bool, struct folio *);
void split_dmabuf_huge_pmd_address(struct vm_area_struct *, unsigned long, bool, struct folio *);
void vma_adjust_dmabuf_huge(struct vm_area_struct *, unsigned long, unsigned long, long);
void __split_dmabuf_huge_range(struct vm_area_struct *);
void split_dmabuf_huge_range(struct vm_area_struct *);
bool move_dmabuf_huge_pmd(struct vm_area_struct *, unsigned long, unsigned long, pmd_t *, pmd_t *, bool);
int dmabuf_huge_remap_pfn_range(struct vm_area_struct *, unsigned long, unsigned long, unsigned long, pgprot_t, unsigned int);
'''
KCONFIG='''
config XIAOMI_DMABUF_HUGETLB
	bool "Recovered rodin DMA-BUF huge mappings (experimental)"
	depends on ARM64 && ARM64_4K_PAGES && ARM64_VA_BITS_39
	depends on TRANSPARENT_HUGEPAGE && HAVE_ARCH_HUGE_VMAP && SMP
	default n
	help
	  Exact DyperOS 3.0.304 rodin PMD/PTE contract. Requires split PMD
	  ptlocks and validated producer alignment/ownership. Do not enable
	  in a shipping kernel until Kbuild/KMI/lifetime/MMU gates pass.

'''


def digest(data):return hashlib.sha256(data).hexdigest()


def replace_exact(text,old,new,count=1):
    if text.count(old)!=count:raise ValueError('nonunique/missing DMA anchor: '+old[:90])
    return text.replace(old,new)


def candidate(source,recipes):
    result=dict(source)
    for name in ('mm/memory.c','mm/mmap.c','mm/mremap.c','mm/huge_memory.c'):
        result[name]=replace_exact(result[name],'#include <linux/mm.h>\n','#include <linux/mm.h>\n#include <linux/xiaomi_dmabuf_huge.h>\n')
    fork='\tif (!vma_needs_copy(dst_vma, src_vma))\n\t\treturn 0;\n'
    result['mm/memory.c']=replace_exact(result['mm/memory.c'],fork,fork+'''#ifdef CONFIG_XIAOMI_DMABUF_HUGETLB
	dmabuf_huge_fork_prepare(dst_vma, src_vma);
#endif
''')
    unmap='\t\tif (is_swap_pmd(*pmd) || pmd_trans_huge(*pmd) || pmd_devmap(*pmd)) {'
    result['mm/memory.c']=replace_exact(result['mm/memory.c'],unmap,'''#ifdef CONFIG_XIAOMI_DMABUF_HUGETLB
		if (vma->vm_flags & VM_XIAOMI_DMABUF_HUGE) {
			if (dmabuf_huge_unmap_prepare(tlb, vma, pmd, addr, next)) {
				addr = next;
				continue;
			}
		} else
#endif
'''+unmap)
    move='again:\n\t\tif (is_swap_pmd(*old_pmd) || pmd_trans_huge(*old_pmd) ||'
    result['mm/mremap.c']=replace_exact(result['mm/mremap.c'],move,'''again:
#ifdef CONFIG_XIAOMI_DMABUF_HUGETLB
		if (vma->vm_flags & VM_XIAOMI_DMABUF_HUGE) {
			if (dmabuf_huge_move_prepare(vma, old_addr, new_addr,
					old_pmd, new_pmd, extent, need_rmap_locks))
				continue;
		} else
#endif
		if (is_swap_pmd(*old_pmd) || pmd_trans_huge(*old_pmd) ||''')
    for old,new,count in (
        ('\tvma_adjust_trans_huge(vma, start, end, 0);',
         '\tdmabuf_huge_adjust_prepare(vma, start, end);',2),
        ('\tvma_adjust_trans_huge(vma, vma->vm_start, addr, 0);',
         '\tdmabuf_huge_adjust_prepare(vma, vma->vm_start, addr);',1)):
        result['mm/mmap.c']=replace_exact(result['mm/mmap.c'],old,'#ifdef CONFIG_XIAOMI_DMABUF_HUGETLB\n'+new+'\n#else\n'+old+'\n#endif',count)
    core='\n#ifdef CONFIG_XIAOMI_DMABUF_HUGETLB\n#if CONFIG_PGTABLE_LEVELS != 3 || !USE_SPLIT_PMD_PTLOCKS\n#error "Recovered DMA requires 3 page-table levels and split PMD locks"\n#endif\n'
    for name in ('pmd_map','contpte_map','pmd_zap','pmd_split'):
        core+='atomic64_t dmabuf_hugetlb_'+name+' = ATOMIC64_INIT(0);\n'
    core+='\n'+''.join(recipes[name]+'\n' for name in ('zap','split','wrappers','range','move','remap'))+'#endif\n'
    result['mm/huge_memory.c']+=core
    header=HEADER
    for name in ('hooks','unmap_hook','move_hook','vma_hook'):
        header+=recipes[name].replace('static void ','static inline void ').replace('static bool ','static inline bool ').replace('(1UL << 39)','VM_XIAOMI_DMABUF_HUGE')+'\n'
    result['include/linux/xiaomi_dmabuf_huge.h']=header+'#endif /* CONFIG_XIAOMI_DMABUF_HUGETLB */\n#endif\n'
    result['mm/Kconfig']=replace_exact(result['mm/Kconfig'],'source "mm/damon/Kconfig"\n\nendmenu',KCONFIG+'source "mm/damon/Kconfig"\n\nendmenu')
    return result


def run(args):
    if args.output.exists():raise ValueError('output must not exist')
    contract=SourceFileLoader('contracts',str(Path(__file__).with_name('verify-stock-recovered-contracts.py'))).load_module()
    if digest(args.image.read_bytes())!=contract.IMAGE_SHA or digest(args.symbols.read_bytes())!=contract.SYMBOL_SHA:
        raise ValueError('stock evidence hash mismatch')
    manifest=json.loads((args.source/'manifest.json').read_text())
    if manifest['commit']!=COMMIT or manifest['repository']!='aosp-mirror/kernel_common':raise ValueError('ACK pin mismatch')
    source={}
    for name,sha in SOURCES.items():
        data=(args.source/name).read_bytes();blob=hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()
        if digest(data)!=sha or manifest['files'][name]['sha256']!=sha or manifest['files'][name]['git_blob']!=blob:raise ValueError('ACK input drift: '+name)
        source[name]=data.decode()
    recipes={};folder=Path(__file__).parents[1]/'tools/stock-recovery'
    for name,sha in RECIPES.items():
        data=(folder/('dmabuf_huge_'+name+'.recovered.c')).read_bytes()
        if digest(data)!=sha:raise ValueError('recipe drift: '+name)
        recipes[name]=data.decode()
    result=candidate(source,recipes)
    args.output.mkdir(parents=True)
    patch=[];changes={}
    for name,text in sorted(result.items()):
        old=source.get(name,'')
        if old==text:continue
        target=args.output/'candidate'/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_text(text)
        patch.extend(difflib.unified_diff(old.splitlines(keepends=True),text.splitlines(keepends=True),fromfile='a/'+name if old else '/dev/null',tofile='b/'+name))
        changes[name]={'before':digest(old.encode()) if old else None,'after':digest(text.encode())}
    (args.output/'dmabuf-review.patch').write_text(''.join(patch))
    report={'status':'REVIEW_ONLY_NOT_INSTALLABLE','ack_commit':COMMIT,'image_sha256':contract.IMAGE_SHA,
            'patch_sha256':digest(''.join(patch).encode()),
            'sources':SOURCES,'recipes':RECIPES,'changes':changes,
            'pending':['Kbuild enabled/disabled','KMI/module audit','producer alignment/ownership/unwind','VMA callbacks/refcounts','MMU/SMP/lifetime/hardware'],
            'safety_deviations':[],
            'preserved_hazards':['PMD remap ignores pmd_set_huge result; no 2MiB extent/alignment guard','ENOMEM leaves partial mappings','adj_next>0 dereferences next before null check']}
    (args.output/'manifest.json').write_text(json.dumps(report,indent=2)+'\n')
    print(f'Prepared {len(changes)} review-only files; no checkout/config/workflow/device changed')


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('source','image','symbols','output'):p.add_argument('--'+name,type=Path,required=True)
    run(p.parse_args())
