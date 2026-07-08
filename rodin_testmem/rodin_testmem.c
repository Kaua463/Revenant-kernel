// SPDX-License-Identifier: GPL-2.0
/*
 * rodin_testmem.c — allocates one kernel page (never swapped, physically
 * contiguous) filled with a known pattern, and exposes its physical address
 * plus a readback of its contents. Used as a SAFE, disposable write target
 * to probe EL3 SMC handlers (e.g. MTK_SIP_APUSYS_CONTROL CE_REG_WRITE)
 * before ever pointing such a call at real hardware/firmware memory.
 *
 * /proc/rodin_testmem/info  -> phys addr (hex) + first 16 bytes (hex)
 * /proc/rodin_testmem/fill  -> write anything to re-arm the known pattern
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include <linux/gfp.h>
#include <linux/mm.h>

#define PATTERN 0xCAFEBABEu

static unsigned long g_page;   /* kernel VA, from __get_free_page */
static phys_addr_t g_phys;

static void fill_pattern(void)
{
	u32 *p = (u32 *)g_page;
	int i;

	for (i = 0; i < PAGE_SIZE / sizeof(u32); i++)
		p[i] = PATTERN;
}

static int info_show(struct seq_file *m, void *v)
{
	u32 *p = (u32 *)g_page;
	int i;

	seq_printf(m, "phys=0x%llx pattern_expected=0x%08x\n",
		   (unsigned long long)g_phys, PATTERN);
	seq_puts(m, "first_32_words:");
	for (i = 0; i < 32; i++)
		seq_printf(m, " %08x", p[i]);
	seq_puts(m, "\n");
	return 0;
}

static int info_open(struct inode *i, struct file *f)
{
	return single_open(f, info_show, NULL);
}

static const struct proc_ops info_ops = {
	.proc_open = info_open,
	.proc_read = seq_read,
	.proc_lseek = seq_lseek,
	.proc_release = single_release,
};

static ssize_t fill_write(struct file *f, const char __user *ubuf,
			   size_t count, loff_t *pos)
{
	fill_pattern();
	pr_info("rodin_testmem: pattern re-armed at phys=0x%llx\n",
		(unsigned long long)g_phys);
	return count;
}

static const struct proc_ops fill_ops = {
	.proc_write = fill_write,
};

static struct proc_dir_entry *dir;

static int __init rodin_testmem_init(void)
{
	g_page = __get_free_page(GFP_KERNEL);
	if (!g_page)
		return -ENOMEM;
	g_phys = virt_to_phys((void *)g_page);
	fill_pattern();

	dir = proc_mkdir("rodin_testmem", NULL);
	if (!dir) {
		free_page(g_page);
		return -ENOMEM;
	}
	proc_create("info", 0444, dir, &info_ops);
	proc_create("fill", 0664, dir, &fill_ops);

	pr_info("rodin_testmem: ready, phys=0x%llx pattern=0x%08x\n",
		(unsigned long long)g_phys, PATTERN);
	return 0;
}

static void __exit rodin_testmem_exit(void)
{
	proc_remove(dir);
	if (g_page)
		free_page(g_page);
}

module_init(rodin_testmem_init);
module_exit(rodin_testmem_exit);

MODULE_DESCRIPTION("Revenant safe disposable test page for EL3 SMC write probing");
MODULE_AUTHOR("Kaua / Revenant");
MODULE_LICENSE("GPL v2");
