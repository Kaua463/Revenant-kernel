#!/usr/bin/env python3
"""Execute exact stock fput; only queue/task-work infrastructure is modeled.

This covers file-reference return for VMA lifetime, not the close caller or
real task-work/destruction/SMP. No zero-reference fput is a valid test input.
"""
import argparse
import hashlib
from importlib.machinery import SourceFileLoader
import json
from pathlib import Path
import struct


def load(name):
    return SourceFileLoader(name, str(Path(__file__).with_name(name))).load_module()


SOURCE_SHA = {'fs/file_table.c': '1e80b584d85be578964e4f7988e669ef534278c25a5b5eb03565e03754a32519',
              'include/linux/fs.h': '52ec871f2520264cdc5aadc08ca2818dacc4040220106a156e8878fac48e63c4',
              'include/linux/sched.h': '0029ba9b9328959dec6fa67953655c810e2dab278980744a978fbd7207f25a69'}


def run(args):
    from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE
    from unicorn.arm64_const import UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X3, UC_ARM64_REG_X30, UC_ARM64_REG_SP, UC_ARM64_REG_SP_EL0, UC_ARM64_REG_PC
    contract = load('verify-stock-recovered-contracts.py')
    image = args.image.read_bytes()
    assert hashlib.sha256(image).hexdigest() == contract.IMAGE_SHA
    assert hashlib.sha256(args.symbols.read_bytes()).hexdigest() == contract.SYMBOL_SHA
    manifest = json.loads((args.source / 'manifest.json').read_text())
    assert manifest['commit'] == 'f7ebe251035c0d15ff90c6a0a320697932785fad'
    for name, sha in SOURCE_SHA.items():
        data = (args.source / name).read_bytes()
        assert hashlib.sha256(data).hexdigest() == sha == manifest['files'][name]['sha256']
        blob = hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()
        assert blob == manifest['files'][name]['git_blob']
    kernel = load('stock-binary-evidence.py').Kernel(args.image, args.symbols)
    fields = load('test-dmabuf-stock-wrappers.py').btf_fields
    for name, expected in {'file': {'f_count': 24, 'f_rcuhead': 0, 'f_llist': 0},
                           'callback_head': {'next': 0, 'func': 8},
                           'thread_info': {'preempt_count': 16},
                           'task_struct': {'thread_info': 0, 'flags': 68}}.items():
        ident = next(i for i, t in enumerate(kernel.btf.types) if t['kind'] == 4 and t['name'] == name)
        actual = fields(kernel.btf, ident)
        assert all(actual[k] == v for k, v in expected.items()), name
    func = next(t for t in kernel.btf.types if t['kind'] == 12 and t['name'] == 'fput')
    proto = kernel.btf.types[func['size']]
    assert proto['kind'] == 13 and proto['size'] == 0 and len(proto['raw']) == 2
    pointer = kernel.btf.types[proto['raw'][1]]
    assert pointer['kind'] == 2 and kernel.btf.types[pointer['size']]['name'] == 'file'
    assert '#define PF_KTHREAD\t\t0x00200000' in (args.source / 'include/linux/sched.h').read_text()
    uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    uc.mem_map(kernel.base, (len(image) + 4095) & ~4095)
    uc.mem_write(kernel.base, image)
    ram = 0x1000000; uc.mem_map(ram, 0x20000)
    file, task, workqueue, stop, stack = ram, ram + 0x2000, ram + 0x4000, ram + 0x10000, ram + 0xf000
    # Runtime-initialized pointer in file-backed data is explicit model state,
    # not a claim that its runtime value was extracted from the stock Image.
    uc.mem_write(kernel.address('system_wq'), struct.pack('<Q', workqueue))
    deferred_list = kernel.address('delayed_fput_list')
    assert kernel.symbols['delayed_fput_list'][0][1] in ('b', 'B') and kernel.span('delayed_fput_list') is None
    names = ('task_work_add', 'llist_add_batch', 'queue_delayed_work_on')
    operations = {kernel.address(name): i for i, name in enumerate(names)}
    trace = []; state = {}; coverage = [0, 0, 0]
    def hook(emu, address, size, user):
        if address in operations:
            op = operations[address]
            values = [emu.reg_read(r) for r in (UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X3)]
            count = struct.unpack('<Q', emu.mem_read(file + 24, 8))[0]
            callback = struct.unpack('<Q', emu.mem_read(file + 8, 8))[0]
            assert count == 0, ('deferred before last reference', count)
            if op == 0:
                assert values[:3] == [task, file, 1]
                assert callback == kernel.address('____fput')
                result = 0 if state['task_ok'] else (1 << 64) - 3
                args = tuple(values[:3])
            elif op == 1:
                assert values[:3] == [file, file, deferred_list]
                result = int(state['empty']); args = tuple(values[:3])
            else:
                assert values == [32, workqueue, kernel.address('delayed_fput_work'), 1]
                result = 1; args = tuple(values)
            trace.append((op, args, count, callback)); coverage[op] += 1
            emu.reg_write(UC_ARM64_REG_X0, result)
            emu.reg_write(UC_ARM64_REG_PC, emu.reg_read(UC_ARM64_REG_X30))
        elif address in (kernel.address('__fput'), kernel.address('____fput')):
            raise AssertionError('fput must not destroy file synchronously')
    uc.hook_add(UC_HOOK_CODE, hook)
    def reset(count, preempt, kthread, task_ok, empty):
        uc.mem_write(file, bytes(264)); uc.mem_write(file, struct.pack('<2Q', 0x2222, 0x3333))
        uc.mem_write(file + 24, struct.pack('<Q', count))
        uc.mem_write(task, bytes(4800)); uc.mem_write(task + 16, struct.pack('<Q', preempt))
        uc.mem_write(task + 68, struct.pack('<I', 0x200000 if kthread else 0))
        state.update(task_ok=task_ok, empty=empty); trace.clear()
    def invoke():
        uc.reg_write(UC_ARM64_REG_X0, file); uc.reg_write(UC_ARM64_REG_X30, stop)
        uc.reg_write(UC_ARM64_REG_SP, stack); uc.reg_write(UC_ARM64_REG_SP_EL0, task)
        uc.emu_start(kernel.address('fput'), stop, count=10000)
        assert uc.reg_read(UC_ARM64_REG_PC) == stop
    cases = 0
    for count in (1, 2, 17, 18, (1 << 63) - 1):
     for preempt in (0, 1, 0x80, 0x100, 0x10000, 0x100000, 0x1000000):
      for kthread in (False, True):
       for task_ok in (False, True):
        for empty in (False, True):
            reset(count, preempt, kthread, task_ok, empty)
            expected = bytearray(uc.mem_read(file, 264)); struct.pack_into('<Q', expected, 24, count - 1)
            routes = []; callback = 0x3333
            if count == 1:
                try_task = not (preempt & 0xffff00) and not kthread
                if try_task:
                    callback = kernel.address('____fput'); struct.pack_into('<Q', expected, 8, callback)
                    routes.append((0, (task, file, 1), 0, callback))
                if not try_task or not task_ok:
                    routes.append((1, (file, file, deferred_list), 0, callback))
                    if empty: routes.append((2, (32, workqueue, kernel.address('delayed_fput_work'), 1), 0, callback))
            invoke()
            assert bytes(uc.mem_read(file, 264)) == bytes(expected), ('file writes', cases)
            assert trace == routes, ('queue routing', cases, trace, routes)
            cases += 1
    # Return the extra split-VMA reference without releasing the original
    # holders, then drop the remaining modeled holders one at a time.
    reset(18, 0, False, True, True)
    for remaining in range(17, -1, -1):
        trace.clear(); invoke()
        assert struct.unpack('<Q', uc.mem_read(file + 24, 8))[0] == remaining
        assert [row[0] for row in trace] == ([] if remaining else [0])
    assert all(coverage), coverage
    print(f'PASS: {cases} exact ARM64 fput cases + 18-drop sequence; queue routes {coverage}; last reference deferred, no synchronous destructor')
    print('Task-work/list/workqueue bodies and runtime system_wq modeled; no close-caller, real queue execution, destructor, SMP or complete VMA lifetime proof.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('image', 'symbols', 'source'):
        parser.add_argument('--' + name, type=Path, required=True)
    run(parser.parse_args())
