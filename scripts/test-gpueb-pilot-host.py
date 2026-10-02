#!/usr/bin/env python3
"""Exercise the actual pilot C with simulated kernel APIs; never access hardware."""
import shutil
import subprocess
import tempfile
from pathlib import Path

root = Path(__file__).resolve().parents[1]
source = root / "tools/gpueb-pilot/gpueb_sram_pilot.c"
shim = r'''
#ifndef PILOT_SHIM_H
#define PILOT_SHIM_H
#include <assert.h>
#include <pthread.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
typedef uint32_t u32;
typedef uint32_t __le32;
typedef int64_t loff_t;
#define __iomem
#define __user
#define __init
#define __exit
#define ERESTARTSYS 512
/* Linux errno values, independent of libc's inclusion of linux/errno.h. */
#define EPERM 1
#define ENXIO 6
#define ENOMEM 12
#define EFAULT 14
#define ENODEV 19
#define EINVAL 22
#define CAP_SYS_RAWIO 17
#define SZ_4K 4096
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#define BUILD_BUG_ON(x) _Static_assert(!(x), "bounds")
#define cpu_to_le32(x) (x)
#define DEFINE_MUTEX(x) pthread_mutex_t x = PTHREAD_MUTEX_INITIALIZER
#define module_init(x)
#define module_exit(x)
#define MODULE_LICENSE(x)
#define MODULE_VERSION(x)
#define MODULE_DESCRIPTION(x)
#define no_llseek NULL
struct file { int unused; };
struct proc_dir_entry { int unused; };
struct device_node { int unused; };
struct resource { uint64_t start, size; };
struct proc_ops {
    ssize_t (*proc_read)(struct file *, char *, size_t, loff_t *);
    void *proc_lseek;
};
static int allow_cap = 1, map_fail, copy_fail, dt_bad = -1, node_missing;
static int node_disabled, name_bad, refs, reads, maps, unmaps, proc_calls;
static struct device_node node;
static struct proc_dir_entry entry;
static uint32_t page[1024];
static int capable(int cap) { assert(cap == CAP_SYS_RAWIO); return allow_cap; }
static int mutex_lock_interruptible(pthread_mutex_t *lock) { return pthread_mutex_lock(lock); }
static void mutex_unlock(pthread_mutex_t *lock) { assert(pthread_mutex_unlock(lock) == 0); }
static void *ioremap(uint64_t address, size_t size) {
    assert(address == 0x13c00000 && size == 4096); maps++;
    return map_fail ? NULL : page;
}
static uint32_t readl(void *address) {
    uintptr_t offset = (uintptr_t)address - (uintptr_t)page;
    uint32_t value;
    assert(offset < 64 && offset % 4 == 0); reads++;
    memcpy(&value, address, sizeof(value)); return value;
}
static void iounmap(void *address) { assert(address == page); unmaps++; }
static ssize_t simple_read_from_buffer(char *out, size_t count, loff_t *pos, const void *in, size_t size) {
    if (copy_fail) return -EFAULT;
    if (*pos < 0) return -EINVAL;
    if ((size_t)*pos >= size) return 0;
    if (count > size - *pos) count = size - *pos;
    memcpy(out, (const char *)in + *pos, count); *pos += count; return count;
}
static struct device_node *of_find_compatible_node(void *a, void *b, const char *name) {
    assert(strcmp(name, "mediatek,gpueb") == 0);
    if (node_missing) return NULL;
    refs++; return &node;
}
static int of_device_is_available(struct device_node *n) { assert(n == &node); return !node_disabled; }
static int of_property_match_string(struct device_node *n, const char *key, const char *name) {
    assert(n == &node && strcmp(key, "reg-names") == 0);
    if (name_bad) return -1;
    if (!strcmp(name, "gpueb_base")) return 0;
    if (!strcmp(name, "gpueb_gpr_base")) return 1;
    if (!strcmp(name, "mbox0_base")) return 4;
    assert(0); return -1;
}
static int of_address_to_resource(struct device_node *n, int index, struct resource *r) {
    assert(n == &node);
    if (index == 0) { r->start = 0x13c00000; r->size = 0x50000; }
    else if (index == 1) { r->start = 0x13c4fd1c; r->size = 0x64; }
    else if (index == 4) { r->start = 0x13c4fd80; r->size = 0x280; }
    else assert(0);
    if (dt_bad == index) r->start++;
    return 0;
}
static void of_node_put(struct device_node *n) { assert(n == &node); refs--; }
static uint64_t resource_size(struct resource *r) { return r->size; }
static struct proc_dir_entry *proc_create(const char *name, unsigned mode, void *parent, const struct proc_ops *ops) {
    assert(!strcmp(name, "gpueb_sram_pilot") && mode == 0400 && parent == NULL);
    assert(ops->proc_lseek == NULL); proc_calls++; return &entry;
}
static void proc_remove(struct proc_dir_entry *p) { assert(p == &entry); }
#endif
'''
main = r'''
static void *reader_thread(void *unused) {
    char buf[64]; loff_t pos = 0;
    assert(pilot_read(NULL, buf, 64, &pos) == 64);
    assert(!memcmp(buf, page, 64)); return NULL;
}
int main(void) {
    char buf[64]; loff_t pos; pthread_t threads[8];
    for (unsigned i = 0; i < ARRAY_SIZE(page); i++) page[i] = 0x01020300 + i;
    for (unsigned i = 0; i < 3; i++) {
        int indices[] = {0, 1, 4}; dt_bad = indices[i];
        assert(pilot_init() == -ENODEV && refs == 0 && proc_calls == 0);
    }
    dt_bad = -1; node_missing = 1;
    assert(pilot_init() == -ENODEV && refs == 0); node_missing = 0;
    node_disabled = 1; assert(pilot_init() == -ENODEV && refs == 0); node_disabled = 0;
    name_bad = 1; assert(pilot_init() == -ENODEV && refs == 0); name_bad = 0;
    assert(pilot_init() == 0 && refs == 0 && proc_calls == 1);
    allow_cap = 0; pos = 0; assert(pilot_read(NULL, buf, 64, &pos) == -EPERM);
    allow_cap = 1; pos = -1; assert(pilot_read(NULL, buf, 64, &pos) == -EINVAL);
    pos = 0; assert(pilot_read(NULL, buf, 0, &pos) == 0);
    pos = 64; assert(pilot_read(NULL, buf, 64, &pos) == 0);
    assert(maps == 0 && reads == 0);
    map_fail = 1; pos = 0; assert(pilot_read(NULL, buf, 64, &pos) == -ENXIO);
    assert(reads == 0 && !snapshot_valid); map_fail = 0;
    copy_fail = 1; assert(pilot_read(NULL, buf, 64, &pos) == -EFAULT);
    assert(snapshot_valid && reads == 16 && unmaps == 1); copy_fail = 0;
    assert(pilot_read(NULL, buf, 7, &pos) == 7 && pos == 7);
    assert(pilot_read(NULL, buf + 7, 57, &pos) == 57 && pos == 64);
    assert(!memcmp(buf, page, 64) && reads == 16);
    /* Simulate fresh module data, then contend on the first capture. */
    snapshot_valid = false;
    for (int i = 0; i < 8; i++) assert(!pthread_create(&threads[i], NULL, reader_thread, NULL));
    for (int i = 0; i < 8; i++) assert(!pthread_join(threads[i], NULL));
    assert(reads == 32 && maps == 3 && unmaps == 2);
    pilot_exit(); puts("Actual pilot C: bounds, DT, capabilities, errors, partial and concurrent reads PASS");
    return 0;
}
'''
compiler = shutil.which("cc")
if not compiler:
    raise SystemExit("C compiler unavailable; test not run")
with tempfile.TemporaryDirectory(prefix="gpueb-pilot-host-") as tmp:
    folder = Path(tmp)
    (folder / "pilot_shim.h").write_text(shim)
    for name in ("errno.h", "capability.h", "io.h", "ioport.h", "kernel.h", "module.h",
                 "mutex.h", "of.h", "of_address.h", "proc_fs.h", "sizes.h", "uaccess.h"):
        header = folder / "linux" / name
        header.parent.mkdir(exist_ok=True)
        header.write_text('#include "pilot_shim.h"\n')
    (folder / "asm").mkdir()
    (folder / "asm/byteorder.h").write_text('#include "pilot_shim.h"\n')
    harness = folder / "test.c"
    harness.write_text(f'#include "{source}"\n' + main)
    binary = folder / "test"
    subprocess.run([compiler, "-std=gnu11", "-Wall", "-Wextra", "-Werror",
                    "-Wno-unused-parameter", "-pthread", "-I", str(folder),
                    str(harness), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
