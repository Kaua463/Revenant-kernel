#!/usr/bin/env python3
"""Download public pinned ACK files; verify each payload against its Git blob ID."""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import subprocess

COMMIT='f7ebe251035c0d15ff90c6a0a320697932785fad'
REPO='aosp-mirror/kernel_common'
FILES=['fs/erofs/internal.h','fs/erofs/super.c','fs/erofs/sysfs.c',
       'fs/erofs/zdata.c','fs/erofs/Kconfig','fs/erofs/Makefile','include/linux/bio.h']


def run(output):
    if output.exists():raise ValueError('preserve old evidence: output must not exist')
    output.mkdir(parents=True)
    manifest={}
    for relative in FILES:
        response=subprocess.run(['gh','api',f'repos/{REPO}/contents/{relative}?ref={COMMIT}'],
                                check=True,capture_output=True,text=True)
        record=json.loads(response.stdout)
        assert record['path']==relative and record['encoding']=='base64'
        data=base64.b64decode(record['content'])
        blob=hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()
        assert blob==record['sha'] and len(data)==record['size']
        path=output/relative;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(data)
        manifest[relative]={'git_blob':blob,'sha256':hashlib.sha256(data).hexdigest(),
                           'url':f'https://github.com/{REPO}/blob/{COMMIT}/{relative}'}
        print(f'{relative}: verified {len(data)} bytes',flush=True)
    (output/'manifest.json').write_text(json.dumps({'repository':REPO,'commit':COMMIT,'files':manifest},indent=2)+'\n')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',type=Path,required=True)
    run(parser.parse_args().output)
