// SPDX-License-Identifier: GPL-2.0
/*
 * rodin_smc.c — generic SMC caller probe, exposes a sysfs interface to issue
 * arbitrary arm_smccc_smc() calls with 6 controllable args (a0..a5), for
 * dynamically testing ATF/BL31 SMC handlers (MTK_SIP_* family) discovered
 * via static analysis, without needing a dedicated kernel module per FID.
 *
 * Safety: exactly one SMC call per write, no retry/loop. Logs full result
 * (a0-a3 of arm_smccc_res) via pr_info and via the readback file.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include <linux/arm-smccc.h>

static unsigned long g_last_args[8];
static struct arm_smccc_res g_last_res;
static int g_last_valid;

static int smc_show(struct seq_file *m, void *v)
{
	seq_puts(m, "write: \"<a0> <a1> <a2> <a3> <a4> <a5> <a6> <a7>\" (all hex, no 0x prefix)\n");
	if (g_last_valid) {
		seq_printf(m, "last call: a0=0x%lx a1=0x%lx a2=0x%lx a3=0x%lx a4=0x%lx a5=0x%lx a6=0x%lx a7=0x%lx\n",
			   g_last_args[0], g_last_args[1], g_last_args[2], g_last_args[3],
			   g_last_args[4], g_last_args[5], g_last_args[6], g_last_args[7]);
		seq_printf(m, "result: a0=0x%lx a1=0x%lx a2=0x%lx a3=0x%lx\n",
			   g_last_res.a0, g_last_res.a1, g_last_res.a2, g_last_res.a3);
	} else {
		seq_puts(m, "no call made yet\n");
	}
	return 0;
}

static ssize_t smc_write(struct file *f, const char __user *ubuf,
			  size_t count, loff_t *pos)
{
	char buf[220], *p, *tok;
	unsigned long args[8] = {0};
	int i;

	if (count == 0 || count >= sizeof(buf))
		return -EINVAL;
	if (copy_from_user(buf, ubuf, count))
		return -EFAULT;
	buf[count] = '\0';
	p = buf;

	for (i = 0; i < 8; i++) {
		tok = strsep(&p, " \t\n");
		if (!tok || !*tok)
			return -EINVAL;
		if (kstrtoul(tok, 16, &args[i]))
			return -EINVAL;
	}

	arm_smccc_smc(args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7], &g_last_res);

	memcpy(g_last_args, args, sizeof(args));
	g_last_valid = 1;

	pr_info("rodin_smc: call a0=0x%lx a1=0x%lx a2=0x%lx a3=0x%lx a4=0x%lx a5=0x%lx a6=0x%lx a7=0x%lx -> res a0=0x%lx a1=0x%lx a2=0x%lx a3=0x%lx\n",
		args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7],
		g_last_res.a0, g_last_res.a1, g_last_res.a2, g_last_res.a3);

	return count;
}

static int smc_open(struct inode *i, struct file *f)
{
	return single_open(f, smc_show, NULL);
}

static const struct proc_ops smc_ops = {
	.proc_open = smc_open,
	.proc_read = seq_read,
	.proc_lseek = seq_lseek,
	.proc_release = single_release,
	.proc_write = smc_write,
};

static struct proc_dir_entry *smc_dir;

static int __init rodin_smc_init(void)
{
	smc_dir = proc_mkdir("rodin_smc", NULL);
	if (!smc_dir)
		return -ENOMEM;
	proc_create("call", 0664, smc_dir, &smc_ops);
	pr_info("rodin_smc: /proc/rodin_smc/call ready\n");
	return 0;
}

static void __exit rodin_smc_exit(void)
{
	proc_remove(smc_dir);
}

module_init(rodin_smc_init);
module_exit(rodin_smc_exit);

MODULE_DESCRIPTION("Revenant generic SMC probe (arm_smccc_smc with 6 args)");
MODULE_AUTHOR("Kaua / Revenant");
MODULE_LICENSE("GPL v2");
