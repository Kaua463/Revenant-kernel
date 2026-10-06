#!/usr/bin/env python3
"""Generate a review-only EROFS source overlay against the exact pinned ACK files.

This NEVER patches the live kernel tree or makes an installable artifact. The
output deliberately remains BLOCKED pending Kbuild, ABI and concurrency gates.
"""
import argparse
import difflib
import hashlib
import importlib.util
import json
from pathlib import Path


def once(text, old, new):
    if text.count(old) != 1:
        raise ValueError('source drift or ambiguous edit anchor: '+repr(old[:100]))
    return text.replace(old,new,1)


def run(args):
    loader=importlib.util.spec_from_file_location('reference',Path(__file__).with_name('fetch-stock-erofs-reference.py'))
    reference=importlib.util.module_from_spec(loader);loader.loader.exec_module(reference)
    if args.output.exists():raise ValueError('new output directory required')
    manifest=json.loads((args.reference/'manifest.json').read_text())
    assert manifest['commit']==reference.COMMIT and manifest['repository']==reference.REPO
    original={}
    for name in reference.FILES:
        data=(args.reference/name).read_bytes()
        assert hashlib.sha256(data).hexdigest()==manifest['files'][name]['sha256']
        assert hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()==manifest['files'][name]['git_blob']
        original[name]=data.decode()
    result=dict(original)
    root=Path(__file__).parents[1]/'tools/stock-recovery'
    config='CONFIG_XIAOMI_EROFS_IOSTAT'
    guard=lambda text:f'#ifdef {config}\n{text}\n#endif\n'
    result['fs/erofs/internal.h']=once(result['fs/erofs/internal.h'],'\tstruct erofs_domain *domain;\n\tchar *fsid;\n\tchar *domain_id;\n};',
        '\tstruct erofs_domain *domain;\n\tchar *fsid;\n\tchar *domain_id;\n'+guard('\tstruct erofs_iostat *iostat;')+'};\n'+
        guard('#include "xiaomi_iostat.h"'))
    # Init BEFORE sysfs publication, unlike stock. Prevent dereference of NULL
    # from a concurrent read of the newly exposed iostat_config attribute.
    result['fs/erofs/super.c']=once(result['fs/erofs/super.c'],'\terr = erofs_register_sysfs(sb);',
        guard('\terr = erofs_init_iostat(sbi);\n\tif (err)\n\t\treturn err;')+'\terr = erofs_register_sysfs(sb);')
    result['fs/erofs/super.c']=once(result['fs/erofs/super.c'],
        '\terofs_fscache_unregister_fs(sb);\n}',
        '\terofs_fscache_unregister_fs(sb);\n'+guard('\terofs_destroy_iostat(sbi);')+'}')
    result['fs/erofs/zdata.c']=once(result['fs/erofs/zdata.c'],'\tstruct bvec_iter_all iter_all;\n\n\tbio_for_each_segment_all',
        '\tstruct bvec_iter_all iter_all;\n\n'+guard('\terofs_iostat_update(EROFS_SB(q->sb), bio);')+'\tbio_for_each_segment_all')
    result['fs/erofs/zdata.c']=once(result['fs/erofs/zdata.c'],'\t\t\t\tbio->bi_end_io = z_erofs_submissionqueue_endio;',
        guard('\t\t\t\terofs_iostat_record_start(EROFS_SB(sb), bio);')+'\t\t\t\tbio->bi_end_io = z_erofs_submissionqueue_endio;')
    text=result['fs/erofs/sysfs.c']
    text=once(text,'\tattr_pointer_bool,','\tattr_pointer_bool,\n'+guard('\tattr_iostat_config,\n\tattr_iostat_window_latency,\n\tattr_iostat_daily_latency,'))
    text=once(text,'\tstruct_erofs_mount_opts,','\tstruct_erofs_mount_opts,\n'+guard('\tstruct_erofs_iostat,'))
    text=once(text,'static struct attribute *erofs_attrs[] = {',
        guard('EROFS_ATTR_RW_BOOL(iostat_enable, erofs_iostat);\nEROFS_ATTR_FUNC(iostat_config, 0644);\nEROFS_ATTR_FUNC(iostat_window_latency, 0444);\nEROFS_ATTR_FUNC(iostat_daily_latency, 0644);')+'static struct attribute *erofs_attrs[] = {')
    text=once(text,'\tATTR_LIST(sync_decompress),\n#endif\n\tNULL,',
        '\tATTR_LIST(sync_decompress),\n#endif\n'+guard('\tATTR_LIST(iostat_enable),\n\tATTR_LIST(iostat_config),\n\tATTR_LIST(iostat_window_latency),\n\tATTR_LIST(iostat_daily_latency),')+'\tNULL,')
    dispatch=(root/'erofs_iostat_sysfs.recovered.c').read_text()
    dispatch=dispatch.replace('erofs_recovered_struct_ptr','__struct_ptr')
    dispatch=once(dispatch,'\tif (struct_type == 2)\n\t\treturn (unsigned char *)sbi->iostat + offset;',guard('\tif (struct_type == 2)\n\t\treturn (unsigned char *)sbi->iostat + offset;').rstrip())
    dispatch=once(dispatch,'\tstruct erofs_iostat *io;',guard('\tstruct erofs_iostat *io;').rstrip())
    start=dispatch.index('\tcase 3:');end=dispatch.index('\n\t}\n\treturn 0;',start)
    dispatch=dispatch[:start]+guard(dispatch[start:end]).rstrip()+dispatch[end:]
    reset='\t\tif (!strcmp(a->attr.name, "iostat_enable") && !sbi->iostat->iostat_enable)\n\t\t\terofs_iostat_latency_stats_reset(sbi);'
    dispatch=once(dispatch,reset,guard(reset).rstrip())
    start=dispatch.index('\tcase 3:',dispatch.index('static ssize_t erofs_attr_store'));end=dispatch.index('\n\t}\n\treturn 0;',start)
    dispatch=dispatch[:start]+guard(dispatch[start:end]).rstrip()+dispatch[end:]
    start=text.index('static unsigned char *__struct_ptr');end=text.index('static void erofs_sb_release',start)
    result['fs/erofs/sysfs.c']=text[:start]+dispatch+'\n'+text[end:]
    result['fs/erofs/Makefile']+='erofs-$(CONFIG_XIAOMI_EROFS_IOSTAT) += xiaomi_iostat.o\n'
    result['fs/erofs/Kconfig']+='\nconfig XIAOMI_EROFS_IOSTAT\n\tbool "Recovered Xiaomi EROFS I/O telemetry (experimental)"\n\tdepends on EROFS_FS\n\tdefault n\n\thelp\n\t  Review-only reconstructed telemetry. Keep disabled pending validation.\n'
    result['fs/erofs/xiaomi_iostat.h']=(root/'erofs_iostat_types.recovered.h').read_text()
    init=(root/'erofs_iostat_init.recovered.c').read_text()
    init=once(init,'\t\tkfree(sbi->iostat);\n\t\t/* Stock does not clear sbi->iostat here. */',
        '\t\tkfree(sbi->iostat);\n\t\tsbi->iostat = NULL; /* Intentional safety deviation from stock. */')
    init=init[init.index('int erofs_init_iostat'):]
    result['fs/erofs/xiaomi_iostat.c']='#include <linux/ktime.h>\n#include <linux/sysfs.h>\n#include "internal.h"\n\n'+init+'\n'+''.join(
        (root/f'erofs_iostat_{part}.recovered.c').read_text()+'\n' for part in ('record_start','update','controls','show'))
    args.output.mkdir(parents=True)
    patch=[];hashes={}
    for name,text in result.items():
        if text==original.get(name):continue
        text=text.rstrip('\n')+'\n'
        destination=args.output/'overlay'/name;destination.parent.mkdir(parents=True,exist_ok=True);destination.write_text(text)
        hashes[name]=hashlib.sha256(text.encode()).hexdigest()
        patch.extend(difflib.unified_diff(original.get(name,'').splitlines(True),text.splitlines(True),
            fromfile='a/'+name if name in original else '/dev/null',tofile='b/'+name))
    (args.output/'REVIEW_ONLY.patch').write_text(''.join(patch))
    report={'status':'BLOCKED_NOT_INSTALLABLE','base_commit':reference.COMMIT,'source_sha256':hashes,
        'intentional_stock_deviations':['Clear freed iostat pointer on percpu allocation failure',
            'Initialize iostat before publishing sysfs attributes'],
        'pending':['Full Kbuild CONFIG=y/n and ZIP=y/n','BTF/KMI/module gate','VFS failure/unmount lifetime tests',
            'SMP update/reset/show concurrency','Prototype, licensing and kernel-style review','Hardware I/O validation']}
    (args.output/'review.json').write_text(json.dumps(report,indent=2)+'\n')
    print(f'Prepared {len(hashes)} changed/new files against {reference.COMMIT}; BLOCKED_NOT_INSTALLABLE')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--reference',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
    run(parser.parse_args())
