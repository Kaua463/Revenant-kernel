#!/usr/bin/env python3
"""Guest VM_SPECIAL topology regression; real C helper, modeled Linux VMAs."""
from importlib.machinery import SourceFileLoader
from pathlib import Path
import hashlib
import json
import os
import subprocess
import tempfile

HERE = Path(__file__).resolve().parent
body = SourceFileLoader('split_move_body', str(HERE/'test-dmabuf-stock-deposit.py')).load_module().body
guest = HERE.parent/'tools/stock-recovery/runtime-audit/guest-workload.c'


def run():
    text = guest.read_text()
    reference = Path(os.environ.get('DMA_ACK_REFERENCE', str(HERE.parents[2]/'outputs/stock-ack-dmabuf-overlay-reference-20261005')))
    manifest = json.loads((HERE.parent/'tools/stock-recovery/overlays/dma-6.6.77/manifest.json').read_text())
    sources = {}
    for name in ('mm/mmap.c', 'mm/mremap.c'):
        data = (reference/name).read_bytes()
        assert hashlib.sha256(data).hexdigest() == manifest['sources'][name], 'ACK topology source drift'
        sources[name] = data.decode()
    assert 'if (vm_flags & VM_SPECIAL)\n\t\treturn NULL;' in sources['mm/mmap.c']
    for name, call in (('static void exercise(', 'move_split_mapping(first, device)'),
                       ('static void exercise_export(', 'move_split_mapping(mappings[3], label)')):
        caller = body(text, name)
        assert caller.index('child = fork()') < caller.index(call)
        assert 'mremap(' not in caller, 'post-fork caller bypasses fragmented-VMA helper'
    fixture = r'''
#define _POSIX_C_SOURCE 200112L
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "audit-data.h"
#define BLOCK (2UL<<20)
#define BYTES (2*BLOCK)
#define SEED UINT64_C(0x8400)
#define MREMAP_MAYMOVE 1
#define MREMAP_FIXED 2
#define PROT_NONE 0
#define MAP_PRIVATE 2
#define MAP_ANONYMOUS 32
#define MAP_FIXED_NOREPLACE 0x100000
#define MAP_FAILED ((void *)-1)
#define MREMAP_DONTUNMAP 4
#define VM_SHARED 1
#define VM_MAYSHARE 2
#define VM_DONTEXPAND 4
#define VM_PFNMAP 8
#define PAGE_SHIFT 12
#define ERR_PTR(n) ((struct vm_area_struct *)(intptr_t)(n))
#define pr_warn_once(...) ((void)0)
struct mm_struct {int unused;};
struct vm_area_struct {unsigned long vm_start,vm_end,vm_flags,vm_pgoff;};
static struct mm_struct mm;
static struct {struct mm_struct *mm;char comm[8];int pid;} task={.mm=&mm}, *current=&task;
static struct vm_area_struct vmas[3];
static struct vm_area_struct *vma_lookup(struct mm_struct *m,unsigned long address){
 assert(m==&mm);for(unsigned i=0;i<3;i++)if(vmas[i].vm_start<=address && address<vmas[i].vm_end)return &vmas[i];return NULL;
}
static int mlock_future_ok(struct mm_struct *m,unsigned long f,unsigned long n){(void)m;(void)f;(void)n;return 1;}
static int may_expand_vm(struct mm_struct *m,unsigned long f,unsigned long n){(void)m;(void)f;(void)n;return 1;}
'''
    modeled = r'''
static void *source, *destination;
static unsigned requests, holes, reservations, moved;
static void fail(const char *s){fprintf(stderr,"%s\n",s);abort();}
static void verify(const void *p,size_t a,size_t b){assert(audit_mismatch(p,a,b,SEED)==SIZE_MAX);}
static void *reservation(size_t n){assert(n==BYTES);assert(!posix_memalign(&destination,BLOCK,n));return destination;}
static void *mremap(void *p,size_t a,size_t b,int flags,void *target){
 const size_t offsets[]={0,BLOCK,BLOCK+4096},lengths[]={BLOCK,4096,BLOCK-4096};
 assert(flags==(MREMAP_MAYMOVE|MREMAP_FIXED) && a==b);
 requests++;
 if(requests==1){assert(p==source && a==BYTES && target==destination);
  struct vm_area_struct *v=vma_to_resize((unsigned long)p,a,b,flags);
  assert(v==ERR_PTR(-EFAULT));holes++;errno=EFAULT;return MAP_FAILED;} /* FIXED removes destination first. */
 assert(reservations==1 && moved<3 && requests==moved+2);
 assert(p==(char *)source+offsets[moved] && a==lengths[moved]);
 assert(target==(char *)destination+offsets[moved]);
 assert(vma_to_resize((unsigned long)p,a,b,flags)==&vmas[moved]);
 memcpy(target,p,a);vmas[moved].vm_start=vmas[moved].vm_end=0;moved++;return target;
}
static int mincore(void *p,size_t n,unsigned char *v){
 assert(p==destination && n==BYTES && v && holes==1 && requests==1);
 errno=ENOMEM;return -1;
}
static void *mmap(void *p,size_t n,int prot,int flags,int fd,long offset){
 assert(p==destination && n==BYTES && prot==PROT_NONE);
 assert(flags==(MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE) && fd==-1 && offset==0);
 assert(holes==1 && requests==1 && reservations==0);reservations++;return p;
}
'''
    main = r'''
int main(void){
 for(unsigned mode=0;mode<2;mode++){
  assert(!posix_memalign(&source,BLOCK,BYTES));audit_fill(source,BYTES,SEED);
  const size_t offsets[]={0,BLOCK,BLOCK+4096},lengths[]={BLOCK,4096,BLOCK-4096};
  for(unsigned i=0;i<3;i++)vmas[i]=(struct vm_area_struct){
   .vm_start=(unsigned long)source+offsets[i],.vm_end=(unsigned long)source+offsets[i]+lengths[i],
   .vm_flags=VM_SHARED|VM_PFNMAP|VM_DONTEXPAND,.vm_pgoff=offsets[i]>>PAGE_SHIFT};
  requests=holes=reservations=moved=0;
  void *result=move_split_mapping(source,mode ? "pte-model":"pmd-model");
  assert(result==destination && requests==4 && holes==1 && reservations==1 && moved==3);
  verify(result,0,BYTES);free(source);free(destination);
 }
 return 0;
}
'''
    code = fixture + body(sources['mm/mremap.c'], 'static struct vm_area_struct *vma_to_resize(') + modeled + body(text, 'static void *move_split_mapping(') + main
    with tempfile.TemporaryDirectory(prefix='dma-split-move-') as temporary:
        binary = Path(temporary)/'test'
        subprocess.run(['clang','-x','c','-std=c11','-Wall','-Wextra','-Werror',
                        '-fsanitize=address,undefined','-fno-sanitize-recover=all',
                        '-I',str(guest.parent),'-o',str(binary),'-'],input=code,text=True,check=True)
        subprocess.run([str(binary)],check=True,timeout=30)
    print('PASS: actual guest helper rejects cross-VMA move, restores owned hole, moves all three VMAs; modeled Linux topology, NOT VM proof')


if __name__ == '__main__':
    run()
