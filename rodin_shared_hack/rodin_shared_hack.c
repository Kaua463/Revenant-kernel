// SPDX-License-Identifier: GPL-2.0
//
// rodin_shared_hack — direct write to GPUEB shared status memory
//
// Premise (from Mayuri-Chan MTK source):
//   AP and GPUEB share a reserved memory region at phys addr 0x7F880000 (rodin
//   DTS gpueb_mem_addr). The struct gpufreq_shared_status lives at offset 0.
//   AP mounts via ioremap_wc — full RW access. GPUEB caches its values but
//   also reads from shared memory for proc display data.
//
// Bypass idea: writing test_mode = TEST_PRIVILEGE (2) directly bypasses the
// IPI gate (CMD_SET_MFGSYS_CONFIG with target=CONFIG_TEST_MODE is dropped by
// GPUEB in retail firmware). After our direct write:
//   - /proc/gpufreqv2/gpufreq_status shows "TestMode: Privilege" (AP reads
//     from shared via g_shared_status)
//   - whitebox_test_proc_write AP-side gate passes (it checks shared)
//   - if GPUEB also reads from shared for fix_custom_freq_volt validation,
//     undervolt unlocked
//
// Struct field offsets (counted from Mayuri-Chan v2/include/gpufreq_v2.h):
//   magic                : 0x000 (int)
//   cur_oppidx_gpu       : 0x004
//   ... 16 more ints ...
//   ... 35 unsigned ints up to 0x120 ...
//   stress_test          : 0x124 (offset 292)
//   test_mode            : 0x128 (offset 296) ← TARGET
//   ips_mode             : 0x12C
//   ... etc
//
// All proven safe paths: read-only by default. Use proc nodes to commit writes.

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/io.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include <linux/string.h>

/* From rodin DTS: /proc/device-tree/soc/gpueb@13c00000/gpueb_mem_addr */
#define GPUEB_SHARED_PA          0x7F880000UL
#define GPUFREQ_SHARED_SIZE      0x4000           /* first sub-region = gpufreq */

/* Offsets in struct gpufreq_shared_status (Mayuri-Chan MT6899 source) */
#define OFF_MAGIC                0x000
#define OFF_CUR_OPPIDX_GPU       0x004
#define OFF_CUR_OPPIDX_STACK     0x008
#define OFF_STRESS_TEST          0x124
#define OFF_TEST_MODE            0x128
#define OFF_IPS_MODE             0x12C
#define OFF_AGING_MARGIN         0x0E4
#define OFF_AVS_MARGIN           0x0EC

/* enum gpufreq_test_mode */
#define TEST_NORMAL              0
#define TEST_ADVANCED            1
#define TEST_PRIVILEGE           2

static void __iomem *shared_va;
static u32 last_set_test_mode;

static int snap_show(struct seq_file *m, void *v)
{
	if (!shared_va) {
		seq_puts(m, "shared_va = NULL (ioremap failed)\n");
		return 0;
	}

	seq_printf(m,
		"phys_base: 0x%lx, size: 0x%x\n"
		"--- shared_status snapshot ---\n"
		"magic           @0x000 = 0x%08x\n"
		"cur_oppidx_gpu  @0x004 = %d\n"
		"cur_oppidx_stk  @0x008 = %d\n"
		"stress_test     @0x124 = %u\n"
		"test_mode       @0x128 = %u  (0=NORMAL 1=ADVANCED 2=PRIVILEGE)\n"
		"ips_mode        @0x12C = %u\n"
		"aging_margin    @0x0E4 = %u\n"
		"avs_margin      @0x0EC = %u\n"
		"--- our last write ---\n"
		"last_set_test_mode = %u\n",
		GPUEB_SHARED_PA, GPUFREQ_SHARED_SIZE,
		readl(shared_va + OFF_MAGIC),
		(int)readl(shared_va + OFF_CUR_OPPIDX_GPU),
		(int)readl(shared_va + OFF_CUR_OPPIDX_STACK),
		readl(shared_va + OFF_STRESS_TEST),
		readl(shared_va + OFF_TEST_MODE),
		readl(shared_va + OFF_IPS_MODE),
		readl(shared_va + OFF_AGING_MARGIN),
		readl(shared_va + OFF_AVS_MARGIN),
		last_set_test_mode);
	return 0;
}

static int snap_open(struct inode *i, struct file *f)
{
	return single_open(f, snap_show, NULL);
}

/* /proc/rodin_shared_hack/test_mode — write integer 0/1/2 to force test_mode */
static ssize_t test_mode_write(struct file *f, const char __user *ub,
			       size_t n, loff_t *o)
{
	char buf[16];
	u32 val;

	if (!shared_va)
		return -ENODEV;
	if (!n || n >= sizeof(buf))
		return -EINVAL;
	if (copy_from_user(buf, ub, n))
		return -EFAULT;
	buf[n] = '\0';
	if (kstrtouint(strim(buf), 0, &val))
		return -EINVAL;
	if (val > 2)
		return -EINVAL;

	writel(val, shared_va + OFF_TEST_MODE);
	/* memory barrier ensures the write reaches RAM before any subsequent read by GPUEB */
	wmb();
	last_set_test_mode = val;

	pr_info("rodin_shared_hack: wrote test_mode=%u at phys=0x%lx+0x%x\n",
		val, GPUEB_SHARED_PA, OFF_TEST_MODE);
	return n;
}

static int test_mode_show(struct seq_file *m, void *v)
{
	if (!shared_va) {
		seq_puts(m, "ENODEV\n");
		return 0;
	}
	seq_printf(m, "%u\n", readl(shared_va + OFF_TEST_MODE));
	return 0;
}

static int test_mode_open(struct inode *i, struct file *f)
{
	return single_open(f, test_mode_show, NULL);
}

/* /proc/rodin_shared_hack/raw_write — "offset value" generic poke (debug) */
static ssize_t raw_write(struct file *f, const char __user *ub,
			 size_t n, loff_t *o)
{
	char buf[64];
	u32 off = 0, val = 0;

	if (!shared_va)
		return -ENODEV;
	if (!n || n >= sizeof(buf))
		return -EINVAL;
	if (copy_from_user(buf, ub, n))
		return -EFAULT;
	buf[n] = '\0';
	if (sscanf(buf, "%x %x", &off, &val) != 2)
		return -EINVAL;
	if (off >= GPUFREQ_SHARED_SIZE - 3 || (off & 3))
		return -EINVAL;

	writel(val, shared_va + off);
	wmb();
	pr_info("rodin_shared_hack: raw write phys=0x%lx+0x%x = 0x%x\n",
		GPUEB_SHARED_PA, off, val);
	return n;
}

static int raw_show(struct seq_file *m, void *v)
{
	seq_puts(m, "write: \"<hex_off> <hex_val>\" (4-byte aligned, off < 0x4000)\n");
	return 0;
}

static int raw_open(struct inode *i, struct file *f)
{
	return single_open(f, raw_show, NULL);
}

static const struct proc_ops snap_ops = {
	.proc_open = snap_open, .proc_read = seq_read,
	.proc_lseek = seq_lseek, .proc_release = single_release,
};

static const struct proc_ops test_mode_ops = {
	.proc_open = test_mode_open, .proc_read = seq_read,
	.proc_lseek = seq_lseek, .proc_release = single_release,
	.proc_write = test_mode_write,
};

static const struct proc_ops raw_ops = {
	.proc_open = raw_open, .proc_read = seq_read,
	.proc_lseek = seq_lseek, .proc_release = single_release,
	.proc_write = raw_write,
};

static struct proc_dir_entry *hack_dir;

static int __init rodin_shared_hack_init(void)
{
	shared_va = ioremap_wc(GPUEB_SHARED_PA, GPUFREQ_SHARED_SIZE);
	if (!shared_va) {
		pr_err("rodin_shared_hack: ioremap_wc(0x%lx) failed\n",
		       GPUEB_SHARED_PA);
		return -ENOMEM;
	}

	hack_dir = proc_mkdir("rodin_shared_hack", NULL);
	if (!hack_dir) {
		iounmap(shared_va);
		shared_va = NULL;
		return -ENOMEM;
	}
	proc_create("snap",      0444, hack_dir, &snap_ops);
	proc_create("test_mode", 0664, hack_dir, &test_mode_ops);
	proc_create("raw_write", 0664, hack_dir, &raw_ops);

	pr_info("rodin_shared_hack: mapped phys 0x%lx (size 0x%x), test_mode read = %u\n",
		GPUEB_SHARED_PA, GPUFREQ_SHARED_SIZE,
		readl(shared_va + OFF_TEST_MODE));
	return 0;
}

static void __exit rodin_shared_hack_exit(void)
{
	proc_remove(hack_dir);
	if (shared_va) {
		iounmap(shared_va);
		shared_va = NULL;
	}
}

module_init(rodin_shared_hack_init);
module_exit(rodin_shared_hack_exit);

MODULE_DESCRIPTION("rodin_shared_hack — direct GPUEB shared memory write (test_mode bypass)");
MODULE_AUTHOR("Kaua / Revenant");
MODULE_LICENSE("GPL v2");
