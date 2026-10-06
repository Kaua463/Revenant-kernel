#!/usr/bin/env python3
"""Pinned SUSFS MM patch commutes with DMA in disposable source trees only."""
import argparse
import hashlib
from importlib.machinery import SourceFileLoader
from pathlib import Path
import shutil
import subprocess
import tempfile

PIN='be7b7ef49a1e1b189c3abf00eacaa7ebdb4168c1'
PATCH_SHA='fb8ed4e7fcd95b01a1bb275c1dd1985f32c72d2997475b94dd39ab4f90775792'
DEF_SHA='4eef49b81b6d8320194284adf02987b7e89df81495f7cdf9de9b29072dd9d87a'


def run(args):
    def get(path):
        return subprocess.run(['git','-C',str(args.susfs_source),'show',PIN+':'+path],check=True,capture_output=True).stdout
    patch=get('kernel_patches/50_add_susfs_in_gki-android15-6.6.patch')
    defs=get('kernel_patches/include/linux/susfs_def.h')
    assert hashlib.sha256(patch).hexdigest()==PATCH_SHA and hashlib.sha256(defs).hexdigest()==DEF_SHA
    # Both use bit 39, but in distinct fields. Do not infer collision by number.
    assert b'#define AS_FLAGS_SUS_MAP 39' in defs
    assert b'inode->i_mapping->flags' in defs and b'vm_flags' not in defs
    paths=[line.split()[2][2:] for line in patch.decode().splitlines() if line.startswith('diff --git ')]
    touched=set(paths)&{'mm/Kconfig','mm/huge_memory.c','mm/memory.c','mm/mmap.c','mm/mremap.c','include/linux/xiaomi_dmabuf_huge.h'}
    assert touched=={'mm/memory.c'},('unexpected SUSFS overlap',touched)
    validator=SourceFileLoader('validate_dma',str(Path(__file__).with_name('validate-dmabuf-overlay.py'))).load_module()
    with tempfile.TemporaryDirectory(prefix='dma-susfs-') as temp:
        temp=Path(temp);p=temp/'susfs.patch';p.write_bytes(patch)
        a=temp/'dma-first';b=temp/'susfs-first';shutil.copytree(args.source,a);shutil.copytree(args.source,b)
        validator.run(argparse.Namespace(source=a,overlay=args.overlay,apply_review=True))
        subprocess.run(['git','apply','--check','--include=mm/memory.c',str(p)],cwd=a,check=True,capture_output=True)
        subprocess.run(['git','apply','--include=mm/memory.c',str(p)],cwd=a,check=True,capture_output=True)
        subprocess.run(['git','apply','--include=mm/memory.c',str(p)],cwd=b,check=True,capture_output=True)
        # Normal validator intentionally rejects altered ACK input. Only this
        # disposable composition test applies the already-validated raw patch.
        try:validator.run(argparse.Namespace(source=b,overlay=args.overlay,apply_review=False))
        except ValueError as error:assert 'input drift' in str(error)
        else:raise AssertionError('normal validator accepted post-SUSFS input')
        dma=str((args.overlay/'dmabuf-review.patch').resolve())
        subprocess.run(['git','apply','--check',dma],cwd=b,check=True,capture_output=True)
        subprocess.run(['git','apply',dma],cwd=b,check=True,capture_output=True)
        for name in validator.prepare.SOURCES:
            assert (a/name).read_bytes()==(b/name).read_bytes(),('composition changes outcome',name)
        assert (a/'include/linux/xiaomi_dmabuf_huge.h').read_bytes()==(b/'include/linux/xiaomi_dmabuf_huge.h').read_bytes()
    print('PASS: exact SUSFS memory.c patch and DMA commute; unchanged recipes/other inputs, separate bit-39 fields; normal preimage gate rejects altered ACK. Not full KSUN/SUSFS/KMI build or runtime proof.')


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('source','overlay','susfs-source'):p.add_argument('--'+name,type=Path,required=True)
    run(p.parse_args())
