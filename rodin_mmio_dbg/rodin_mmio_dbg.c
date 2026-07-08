// SPDX-License-Identifier: GPL-2.0
/*
 * rodin_mmio_dbg.c — raw physical memory read/write probe, same spirit as
 * MTK's own mtk-spmi-pmic-debug.c but for arbitrary MMIO/SRAM physical
 * addresses instead of SPMI registers.
 *
 * Purpose: investigate the GPUEB live OPP table SRAM address documented in
 * a prior session (0x13c264d8), to determine whether the AP side can read
 * and/or write the SOURCE voltage values GPUEB computes its DVFS commit
 * from (as opposed to fighting the constantly-recalculated VOSEL register
 * on the MT6316 PMIC, which loses the race under real load).
 *
 * Safety: /proc/rodin_mmio/read (write-only trigger, "addr size" in hex)
 * only ioremaps and reads, logging the result via pr_info -- never writes.
 * /proc/rodin_mmio/write ("addr val" in hex) performs exactly one writel
 * per invocation, no retry/loop. A region gated by DEVAPC may raise a bus
 * fault (SError) on access; this module does not attempt to trap or
 * recover from that -- test read first, and only write with explicit,
 * separate confirmation for each address.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include <linux/io.h>

static u64 g_last_addr;
static u32 g_last_size;
static u32 g_last_val;
static int g_last_ret;

static int read_show(struct seq_file *m, void *v)
{
	seq_puts(m, "write: \"<phys_addr_hex> <size_bytes_hex:1|2|4>\"\n");
	seq_printf(m, "last: addr=0x%llx size=%u val=0x%x ret=%d\n",
		   g_last_addr, g_last_size, g_last_val, g_last_ret);
	return 0;
}

static ssize_t read_write(struct file *f, const char __user *ubuf,
			   size_t count, loff_t *pos)
{
	char buf[64], *p, *tok;
	u64 addr;
	u32 size;
	void __iomem *base;
	u32 val = 0;

	if (count == 0 || count >= sizeof(buf))
		return -EINVAL;
	if (copy_from_user(buf, ubuf, count))
		return -EFAULT;
	buf[count] = '\0';
	p = buf;

	tok = strsep(&p, " \t\n");
	if (!tok || kstrtou64(tok, 16, &addr))
		return -EINVAL;
	tok = strsep(&p, " \t\n");
	if (!tok || kstrtou32(tok, 16, &size))
		return -EINVAL;

	/* alignment fault on readl/readw is fatal in EL1 (no recovery path
	 * here) -- a prior test crashed the kernel this way. Reject anything
	 * not naturally aligned instead of trusting the caller. */
	if ((size != 1 && size != 2 && size != 4) ||
	    (size == 2 && (addr & 0x1)) ||
	    (size == 4 && (addr & 0x3))) {
		pr_err("rodin_mmio: rejected unaligned/invalid read addr=0x%llx size=%u\n",
		       addr, size);
		g_last_ret = -EINVAL;
		return count;
	}

	base = ioremap(addr, 4);
	if (!base) {
		pr_err("rodin_mmio: ioremap(0x%llx) failed\n", addr);
		g_last_ret = -ENOMEM;
		return count;
	}

	if (size == 1)
		val = readb(base);
	else if (size == 2)
		val = readw(base);
	else
		val = readl(base);

	iounmap(base);

	g_last_addr = addr;
	g_last_size = size;
	g_last_val = val;
	g_last_ret = 0;

	pr_info("rodin_mmio: read addr=0x%llx size=%u -> val=0x%x\n", addr, size, val);
	return count;
}

static int write_show(struct seq_file *m, void *v)
{
	seq_puts(m, "write: \"<phys_addr_hex> <val_hex>\" -- ONE writel per call, no retry\n");
	seq_printf(m, "last write: addr=0x%llx val=0x%x ret=%d\n",
		   g_last_addr, g_last_val, g_last_ret);
	return 0;
}

static ssize_t write_write(struct file *f, const char __user *ubuf,
			    size_t count, loff_t *pos)
{
	char buf[64], *p, *tok;
	u64 addr;
	u32 val;
	void __iomem *base;

	if (count == 0 || count >= sizeof(buf))
		return -EINVAL;
	if (copy_from_user(buf, ubuf, count))
		return -EFAULT;
	buf[count] = '\0';
	p = buf;

	tok = strsep(&p, " \t\n");
	if (!tok || kstrtou64(tok, 16, &addr))
		return -EINVAL;
	tok = strsep(&p, " \t\n");
	if (!tok || kstrtou32(tok, 16, &val))
		return -EINVAL;

	if (addr & 0x3) {
		pr_err("rodin_mmio: rejected unaligned write addr=0x%llx\n", addr);
		g_last_ret = -EINVAL;
		return count;
	}

	base = ioremap(addr, 4);
	if (!base) {
		pr_err("rodin_mmio: ioremap(0x%llx) failed for write\n", addr);
		g_last_ret = -ENOMEM;
		return count;
	}

	writel(val, base);
	iounmap(base);

	g_last_addr = addr;
	g_last_val = val;
	g_last_ret = 0;

	pr_info("rodin_mmio: WRITE addr=0x%llx val=0x%x\n", addr, val);
	return count;
}

#define MMIO_RW(nm)							\
static int nm##_open(struct inode *i, struct file *f)			\
{ return single_open(f, nm##_show, NULL); }				\
static const struct proc_ops nm##_ops = {				\
	.proc_open = nm##_open, .proc_read = seq_read,			\
	.proc_lseek = seq_lseek, .proc_release = single_release,	\
	.proc_write = nm##_write,					\
}

MMIO_RW(read);
MMIO_RW(write);

static struct proc_dir_entry *mmio_dir;

static int __init rodin_mmio_init(void)
{
	mmio_dir = proc_mkdir("rodin_mmio", NULL);
	if (!mmio_dir)
		return -ENOMEM;
	proc_create("read", 0664, mmio_dir, &read_ops);
	proc_create("write", 0664, mmio_dir, &write_ops);
	pr_info("rodin_mmio: /proc/rodin_mmio ready\n");
	return 0;
}

static void __exit rodin_mmio_exit(void)
{
	proc_remove(mmio_dir);
}

module_init(rodin_mmio_init);
module_exit(rodin_mmio_exit);

MODULE_DESCRIPTION("Revenant raw physical MMIO/SRAM read-write probe");
MODULE_AUTHOR("Kaua / Revenant");
MODULE_LICENSE("GPL v2");
