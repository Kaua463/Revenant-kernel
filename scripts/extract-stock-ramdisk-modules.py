#!/usr/bin/env python3
"""Stream newc ramdisks; extract ONLY regular lib/modules/*.ko to a fresh folder.

No cpio execution, symlink following, permission restoration or device access.
Reject unsafe paths, duplicate selected paths, unsupported hard links/truncation.
"""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import shutil
import stat
import subprocess


def read_exact(stream, size):
    data=stream.read(size)
    if len(data)!=size:raise ValueError('truncated newc stream')
    return data


def extract(stream, output):
    if output.exists():raise ValueError('output must not exist')
    output.mkdir(parents=True)
    rows=[];seen=set();total=0;entries=0
    while True:
        header=read_exact(stream,110)
        if header[:6] not in (b'070701',b'070702'):raise ValueError('not newc archive')
        fields=[int(header[6+i*8:14+i*8],16) for i in range(13)]
        mode,nlink,size,namesize,check=fields[1],fields[4],fields[6],fields[11],fields[12]
        if not 1<=namesize<=4096 or size>256*1024*1024:raise ValueError('newc member bounds')
        name_bytes=read_exact(stream,namesize)
        if name_bytes[-1:]!=b'\0' or b'\0' in name_bytes[:-1]:raise ValueError('invalid newc name')
        name=name_bytes[:-1].decode('utf-8','strict')
        read_exact(stream,(-110-namesize)%4)
        path=PurePosixPath(name)
        if path.is_absolute() or '..' in path.parts:raise ValueError('unsafe newc path')
        if name=='TRAILER!!!':
            if size:raise ValueError('nonempty trailer')
            break
        entries+=1;total+=size
        if entries>100000 or total>2*1024*1024*1024:raise ValueError('archive bounds')
        parts=path.parts
        selected=any(parts[i:i+2]==('lib','modules') for i in range(len(parts)-1)) and name.endswith('.ko')
        destination=None
        if selected:
            if not stat.S_ISREG(mode) or nlink!=1:raise ValueError('selected module is not standalone regular file')
            if path.as_posix() in seen:raise ValueError('duplicate module path')
            seen.add(path.as_posix())
            destination=output/path;destination.parent.mkdir(parents=True,exist_ok=True)
        digest=hashlib.sha256();checksum=0;remaining=size
        target=destination.open('xb') if destination else None
        try:
            while remaining:
                chunk=read_exact(stream,min(remaining,1024*1024));remaining-=len(chunk)
                if selected:digest.update(chunk);target.write(chunk)
                if header[:6]==b'070702':checksum=(checksum+sum(chunk))&0xffffffff
        finally:
            if target:target.close()
        if header[:6]==b'070702' and checksum!=check:raise ValueError('newc data checksum')
        read_exact(stream,(-size)%4)
        if selected:rows.append({'path':path.as_posix(),'bytes':size,'sha256':digest.hexdigest()})
    # Consume padding so decompressor cannot fail unnoticed or block on pipe.
    while True:
        tail=stream.read(1024*1024)
        if not tail:break
        if any(tail):raise ValueError('nonzero trailing bytes / concatenated archive unsupported')
    if not rows:raise ValueError('archive contains no selected modules')
    return {'schema':1,'selected_count':len(rows),'archive_entries':entries,'modules':rows}


def run(args):
    signature=args.ramdisk.open('rb').read(4)
    if signature==b'\x28\xb5\x2f\xfd':command=['zstd','-d','-c',str(args.ramdisk)]
    elif signature in (b'\x02\x21\x4c\x18',b'\x04\x22\x4d\x18'):command=['lz4','-d','-c',str(args.ramdisk)]
    else:raise ValueError('unsupported ramdisk compression')
    command[0]=shutil.which(command[0]) or command[0]
    process=subprocess.Popen(command,stdout=subprocess.PIPE)
    try:
        report=extract(process.stdout,args.output)
        if process.wait()!=0:raise ValueError('decompression failed')
    except BaseException:
        process.kill();process.wait();raise
    report['input_sha256']=hashlib.sha256(args.ramdisk.read_bytes()).hexdigest()
    (args.output/'manifest.json').write_text(json.dumps(report,indent=2)+'\n')
    print(f'Extracted {report["selected_count"]} regular modules only; other {report["archive_entries"]-report["selected_count"]} entries skipped')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ramdisk',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
    run(parser.parse_args())
