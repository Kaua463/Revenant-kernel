#!/usr/bin/env python3
"""Generate a pinned, default-off DMA core callback extension; no input edits."""
import argparse
import difflib
import hashlib
from importlib.machinery import SourceFileLoader
import json
from pathlib import Path

proof = SourceFileLoader('dma_address_proof', str(Path(__file__).with_name('extract-dmabuf-address-selector.py'))).load_module()
RECIPE_SHA = '12bd968b8d17db819557094d43db1990fef0b50c3bf694e0fda398d0997c6878'
PATH = 'drivers/dma-buf/dma-buf.c'
FOPS = 'static const struct file_operations dma_buf_fops = {\n'
GUARD = 'CONFIG_XIAOMI_DMABUF_HUGETLB'


def candidate(core, recipe):
    if core.count(FOPS) != 1 or 'dma_buf_hugetlb_get_unmapped_area' in core:
        raise ValueError('core callback anchor drift/already integrated')
    prefix = '#ifdef ' + GUARD + '\n' + recipe + '\n#endif\n\n'
    registration = '#ifdef ' + GUARD + '\n\t.get_unmapped_area = dma_buf_hugetlb_get_unmapped_area,\n#endif\n'
    return core.replace(FOPS, prefix + FOPS + registration)


def run(args):
    if args.output.exists() or args.output.is_symlink():
        raise ValueError('output must not exist')
    recipe_path = Path(__file__).parents[1]/'tools/stock-recovery/dmabuf_huge_address.recovered.c'
    core, recipe = args.core.read_bytes(), recipe_path.read_bytes()
    if args.core.is_symlink() or hashlib.sha256(core).hexdigest() != proof.CORE_SHA:
        raise ValueError('ACK core drift')
    if hashlib.sha256(recipe).hexdigest() != RECIPE_SHA:
        raise ValueError('selector recipe drift')
    result = candidate(core.decode(), recipe.decode())
    patch = ''.join(difflib.unified_diff(core.decode().splitlines(keepends=True),
                                      result.splitlines(keepends=True), fromfile='a/'+PATH, tofile='b/'+PATH))
    args.output.mkdir(parents=True)
    target = args.output/'candidate'/PATH
    target.parent.mkdir(parents=True)
    target.write_text(result)
    (args.output/'dmabuf-address-review.patch').write_text(patch)
    report = {'status':'REVIEW_ONLY_NOT_INSTALLABLE',
              'ack_commit':'f7ebe251035c0d15ff90c6a0a320697932785fad',
              'guard':GUARD, 'requires_base_overlay':True,
              'changes':{PATH:{'before':proof.CORE_SHA,'after':hashlib.sha256(result.encode()).hexdigest()}},
              'recipe_sha256':RECIPE_SHA,'patch_sha256':hashlib.sha256(patch.encode()).hexdigest(),
              'pending':['Kbuild enabled/disabled','real DMA-BUF VFS callback workload',
                         'KMI/modules','complete failure/lifetime/MMU/SMP/hardware gates']}
    (args.output/'manifest.json').write_text(json.dumps(report,indent=2)+'\n')
    print('Prepared one guarded DMA core extension; source/production overlay/device unchanged')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--core',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    run(parser.parse_args())
