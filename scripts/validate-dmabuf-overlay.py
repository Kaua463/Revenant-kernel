#!/usr/bin/env python3
"""Validate/apply the review-only DMA patch to a disposable pinned build tree."""
import argparse
import difflib
import hashlib
from importlib.machinery import SourceFileLoader
import json
from pathlib import Path
import subprocess

prepare=SourceFileLoader('prepare_dma',str(Path(__file__).with_name('prepare-dmabuf-reimplementation.py'))).load_module()


def run(args):
    report=json.loads((args.overlay/'manifest.json').read_text())
    patch=args.overlay/'dmabuf-review.patch'
    if (report['status']!='REVIEW_ONLY_NOT_INSTALLABLE' or report['ack_commit']!=prepare.COMMIT or
        report['sources']!=prepare.SOURCES or report['recipes']!=prepare.RECIPES):raise ValueError('overlay contract/pin mismatch')
    if report.get('safety_deviations')!=prepare.SAFETY_DEVIATIONS:
        raise ValueError('overlay safety deviations mismatch')
    if hashlib.sha256(patch.read_bytes()).hexdigest()!=report['patch_sha256']:raise ValueError('patch hash mismatch')
    expected={'mm/Kconfig','mm/huge_memory.c','mm/memory.c','mm/mmap.c','mm/mremap.c','include/linux/xiaomi_dmabuf_huge.h'}
    if set(report['changes'])!=expected:raise ValueError('overlay write scope mismatch')
    folder=Path(__file__).parents[1]/'tools/stock-recovery'
    recipes={};source={}
    for name,sha in prepare.RECIPES.items():
        data=(folder/('dmabuf_huge_'+name+'.recovered.c')).read_bytes()
        if hashlib.sha256(data).hexdigest()!=sha:raise ValueError('recipe drift')
        recipes[name]=data.decode()
    for name,sha in prepare.SOURCES.items():
        path=args.source/name
        if path.is_symlink() or hashlib.sha256(path.read_bytes()).hexdigest()!=sha:raise ValueError('ACK input drift: '+name)
        source[name]=path.read_text()
    result=prepare.candidate(source,recipes);canonical=[]
    for name,text in sorted(result.items()):
        old=source.get(name,'')
        if old==text:continue
        if report['changes'][name]['after']!=hashlib.sha256(text.encode()).hexdigest():raise ValueError('candidate hash mismatch')
        canonical.extend(difflib.unified_diff(old.splitlines(keepends=True),text.splitlines(keepends=True),fromfile='a/'+name if old else '/dev/null',tofile='b/'+name))
    if patch.read_text()!=''.join(canonical):raise ValueError('patch differs from pinned recipes/anchors')
    for name,record in report['changes'].items():
        if record['before']!=prepare.SOURCES.get(name):raise ValueError('before hash contract mismatch')
        if record['before'] is None and (args.source/name).exists():raise ValueError('new header already exists')
    names=subprocess.run(['git','apply','--numstat',str(patch.resolve())],cwd=args.source,check=True,capture_output=True,text=True)
    if {line.split('\t')[2] for line in names.stdout.splitlines()}!=expected:raise ValueError('patch path mismatch')
    subprocess.run(['git','apply','--check',str(patch.resolve())],cwd=args.source,check=True)
    if args.apply_review:
        subprocess.run(['git','apply',str(patch.resolve())],cwd=args.source,check=True)
        for name,record in report['changes'].items():
            if hashlib.sha256((args.source/name).read_bytes()).hexdigest()!=record['after']:raise ValueError('post-apply hash mismatch: '+name)
    print('PASS: pinned DMA overlay '+('applied to build tree' if args.apply_review else 'dry-run')+'; still REVIEW_ONLY_NOT_INSTALLABLE')


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source',type=Path,required=True);p.add_argument('--overlay',type=Path,required=True)
    p.add_argument('--apply-review',action='store_true');run(p.parse_args())
