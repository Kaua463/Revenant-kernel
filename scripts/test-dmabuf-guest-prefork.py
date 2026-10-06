#!/usr/bin/env python3
"""Actual guest helper with native reader and modeled Linux syscalls; not VM proof."""
from importlib.machinery import SourceFileLoader
from pathlib import Path
import subprocess
import tempfile

HERE=Path(__file__).resolve().parent
extract=SourceFileLoader('prefork_body_extract',str(HERE/'test-dmabuf-stock-deposit.py')).load_module().body
guest=HERE.parent/'tools/stock-recovery/runtime-audit/guest-workload.c'


def run():
    text=guest.read_text()
    # Source ordering is part of the coverage gate, not merely presence of calls.
    for function, call in (('static void exercise(', 'verify_prefork_lifecycle(&first'),
                           ('static void exercise_export(', 'verify_prefork_lifecycle(&mappings[3]')):
        body=extract(text,function)
        assert body.index(call)<body.index('child = fork()'), 'special flag lost before test'
        assert body.index('close(fd)')<body.index(call), 'test must exercise VMA-owned backing'
    fixture=r'''
#define _POSIX_C_SOURCE 200112L
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
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
#define PROT_READ 1
#define PROT_WRITE 2
#define MADV_DONTNEED 4
struct reader {const void *alias;size_t bytes;atomic_int stop;atomic_ulong passes;};
static unsigned moved_count,protect_count,discard_count,migrated_count;
static void fail(const char *s){fprintf(stderr,"%s\n",s);abort();}
static void verify(const void *p,size_t a,size_t b){assert(audit_mismatch(p,a,b,SEED)==SIZE_MAX);}
static void *reservation(size_t n){void *p;assert(!posix_memalign(&p,BLOCK,n));return p;}
static void *mremap(void *p,size_t a,size_t b,int flags,void *target){
 assert(a==BYTES && b==BYTES && flags==(MREMAP_MAYMOVE|MREMAP_FIXED));
 moved_count++;memcpy(target,p,a);free(p);return target;}
static int mprotect(void *p,size_t n,int flags){assert(p && moved_count==1);
 if(protect_count<2)assert(n==BYTES);else assert(n==4096);
 assert(flags==(protect_count%2 ? PROT_READ|PROT_WRITE : PROT_NONE));protect_count++;return 0;}
static int madvise(void *p,size_t n,int advice){assert(p && n==BYTES && protect_count==4 && advice==MADV_DONTNEED);
 discard_count++;errno=EINVAL;return -1;}
static void migrate_and_verify(const void *p){assert(protect_count==4 && discard_count==1);
 verify(p,0,BYTES);migrated_count++;} /* CPU affinity modeled in native test. */
'''
    main=r'''
int main(void){
 for(unsigned short_alias=0;short_alias<2;short_alias++){
  void *first=reservation(BYTES),*alias=reservation(short_alias?BLOCK:BYTES);
  audit_fill(first,BYTES,SEED);audit_fill(alias,short_alias?BLOCK:BYTES,SEED);
  moved_count=protect_count=discard_count=migrated_count=0;
  verify_prefork_lifecycle(&first,alias,short_alias?BLOCK:BYTES,"native-model");
  assert(moved_count==1 && protect_count==4 && discard_count==1 && migrated_count==1);
  verify(first,0,BYTES);verify(alias,0,short_alias?BLOCK:BYTES);
  free(first);free(alias);
 }
 return 0;
}
'''
    code=fixture+extract(text,'static void *read_alias(')+extract(text,'static void verify_prefork_lifecycle(')+main
    with tempfile.TemporaryDirectory(prefix='dma-prefork-native-') as temporary:
        binary=Path(temporary)/'test'
        subprocess.run(['clang','-x','c','-std=c11','-Wall','-Wextra','-Werror','-pthread',
                        '-fsanitize=address,undefined','-fno-sanitize-recover=all',
                        '-I',str(guest.parent),'-o',str(binary),'-'],input=code,text=True,check=True)
        subprocess.run([str(binary)],check=True,timeout=30)
    print('PASS: pre-fork source ordering + actual concurrent data reader/full-and-short aliases; Linux syscalls modeled, NOT VM/MMU proof')


if __name__=='__main__':run()
