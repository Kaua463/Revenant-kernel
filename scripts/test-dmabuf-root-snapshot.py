#!/usr/bin/env python3
"""Real pinned ACK/SUSFS kernel-side root snapshot -> DMA; not full KSU build.

Only 36 root/MM inputs plus one pinned core input in a disposable fixture. No toolchain,
kernel compilation, KSU patch execution, device access or shipping evidence.
"""
import argparse
import hashlib
from importlib.machinery import SourceFileLoader
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile

HERE=Path(__file__).resolve().parent
driver=SourceFileLoader('dma_real_root_snapshot',str(HERE/'integrate-dmabuf-after-root.py')).load_module()
INTEGRATOR_SHA='e4d0ae20f9d00de47456a11afcd9c49169ccc2658697f4c1f0ad40157de40b17'


def run(args):
    manifest=json.loads((args.source/'manifest.json').read_text())
    if (manifest['repository']!='aosp-mirror/kernel_common' or
        manifest['commit']!=driver.composition.validator.prepare.COMMIT):
        raise ValueError('ACK reference identity mismatch')
    patch=subprocess.check_output(['git','-C',str(args.susfs_source),'show',
                                   driver.composition.PIN+':'+driver.composition.PATCH_PATH])
    if hashlib.sha256(patch).hexdigest()!=driver.composition.PATCH_SHA:
        raise ValueError('SUSFS patch identity mismatch')
    paths={line.split()[2][2:] for line in patch.decode().splitlines()
           if line.startswith('diff --git ')}
    paths.update(driver.composition.validator.prepare.SOURCES)
    paths.update(('drivers/Kconfig','drivers/Makefile'))
    if len(paths)!=36 or set(manifest['files'])!=paths:
        raise ValueError('exact 36-input kernel-side snapshot required')
    integrator=(HERE/'integrate-ksun-susfs-6.6.77.sh').read_bytes()
    if hashlib.sha256(integrator).hexdigest()!=INTEGRATOR_SHA:
        raise ValueError('root adaptation script drift')
    fragments=re.findall(r'python3 - "\$KERNEL_DIR" <<\x27PY\x27\n(.*?)\nPY',
                         integrator.decode(),re.S)
    if len(fragments)!=2:
        raise ValueError('unique kernel adaptation and manifest fragments required')
    with tempfile.TemporaryDirectory(prefix='dma-pinned-root-snapshot-') as temporary:
        tree=Path(temporary)
        for name in sorted(paths):
            data=(args.source/name).read_bytes()
            record=manifest['files'][name]
            blob=hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()
            if hashlib.sha256(data).hexdigest()!=record['sha256'] or blob!=record['git_blob']:
                raise ValueError('ACK source drift: '+name)
            target=tree/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(data)
        core=args.core.read_bytes()
        if hashlib.sha256(core).hexdigest()!=driver.address.proof.CORE_SHA:
            raise ValueError('core source drift')
        target=tree/driver.address.PATH;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(core)
        subprocess.run(['git','init','-q',str(tree)],check=True)
        subprocess.run(['git','-C',str(tree),'add','.'],check=True)
        subprocess.run(['git','-C',str(tree),'-c','user.name=DMA fixture',
                        '-c','user.email=dma-fixture@example.invalid','commit','-qm',
                        'Disposable pinned public source fixture'],check=True)
        result=subprocess.run(['patch','--batch','--forward','--fuzz=0','-p1'],
                              cwd=tree,input=patch,capture_output=True)
        rejects=sorted(str(p.relative_to(tree)) for p in tree.rglob('*.rej'))
        if result.returncode==0 or rejects!=['fs/exec.c.rej','fs/proc/base.c.rej','fs/proc/task_mmu.c.rej']:
            raise ValueError('unexpected kernel-side root reject set: '+repr(rejects))
        # Execute only the exact audited kernel adaptation fragment in this
        # fixture. The KSU-side patching/build remains a separate pending gate.
        subprocess.run([sys.executable,'-',str(tree)],input=fragments[0],text=True,check=True)
        for name,line in (('drivers/Makefile','obj-$(CONFIG_KSU) += kernelsu/'),
                          ('drivers/Kconfig','source "drivers/kernelsu/Kconfig"')):
            target=tree/name;target.write_bytes(target.read_bytes()+('\n'+line+'\n').encode())
        for name,sha in driver.COPIED.items():
            data=subprocess.check_output(['git','-C',str(args.susfs_source),'show',
                                          driver.composition.PIN+':kernel_patches/'+name])
            if hashlib.sha256(data).hexdigest()!=sha:
                raise ValueError('copied source drift')
            (tree/name).write_bytes(data)
        root_names=driver.root_gate(tree)
        snapshot={name:driver.composition.digest(driver.composition.payload(tree,name)) for name in root_names}
        report=driver.composition.run(argparse.Namespace(source=tree,ack_reference=args.source,
                          overlay=args.overlay,susfs_source=args.susfs_source,apply_review=True,output=None))
        prepared=tree/'audit-core-overlay'
        driver.address.run(argparse.Namespace(core=tree/driver.address.PATH,output=prepared))
        driver.compose_core(tree,prepared,report)
        expected=driver.expected_composed_manifest(snapshot,report)
        names=driver.changed(tree)
        if len(names)!=31 or driver.ordered_manifest(tree,names)!=expected:
            raise ValueError('actual composed source manifest mismatch')
        if expected!=driver.COMPOSED_MANIFEST:
            raise ValueError('verified source snapshot differs from composed pin: '+expected)
        try:
            driver.compose_core(tree,prepared,report)
        except ValueError as error:
            if 'preimage drift' not in str(error):
                raise
        else:
            raise ValueError('repeat core composition accepted')
        if driver.ordered_manifest(tree,names)!=expected:
            raise ValueError('rejected repeat changed source')
        for name,sha in driver.COPIED.items():
            if driver.composition.digest(driver.composition.payload(tree,name))!=sha:
                raise ValueError('DMA changed copied SUSFS source')
        # Changing an otherwise unrelated root file must fail the final gate.
        target=tree/'fs/open.c';target.write_bytes(target.read_bytes()+b'/* unexpected delta */\n')
        if driver.ordered_manifest(tree,names)==expected:
            raise ValueError('unexpected root mutation escaped composed gate')
    print('PASS: actual 26-file pinned kernel-side root snapshot -> 31-file MM/core DMA composition; '+
          'independent expected SHA256='+expected+'; NOT full KSU integration/Kbuild/KMI/runtime proof')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('source','susfs-source','overlay','core'):
        parser.add_argument('--'+name,type=Path,required=True)
    run(parser.parse_args())
