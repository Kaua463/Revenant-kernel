// SPDX-License-Identifier: GPL-2.0
//
// rodin_smc_probe — SMC FID enumerator via arm_smccc_smc()
//
// Goal: brute-force MTK SiP FID range (0x82000000-0x820006FF) and identify
// which handlers respond (= exist + accept call). Result code distinguishes:
//   SMC_UNKNOWN_FUNCTION (0xFFFFFFFFL or 0xFFFFFFFF as int)  → handler missing
//   anything else (including 0=success, -1, etc)              → handler exists
//
// Safety: args[1..6] = 0. Most MTK handlers interpret arg0 as subcmd_id.
//   subcmd_id=0 typically means "info/version" → safe read-only.
// We monitor /proc/devapc_dbg before/after to confirm no DEVAPC fires.
//
// Procs:
//   /proc/rodin_smc_probe/single  : write "<hex_fid>" → single SMC call
//   /proc/rodin_smc_probe/range   : write "<start> <end>" → scan range
//   /proc/rodin_smc_probe/result  : read recent results

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/arm-smccc.h>
#include <linux/delay.h>

#define MAX_RESULTS 2048
#define SMC_UNKNOWN_LOW32 0xFFFFFFFFU

struct probe_result {
	u32 fid;
	u64 a0, a1, a2, a3;
};

static struct probe_result *results;
static int result_count;
static DEFINE_MUTEX(probe_lock);

static void do_smc(u32 fid)
{
	struct arm_smccc_res res = {0};
	struct probe_result *r;

	arm_smccc_smc(fid, 0, 0, 0, 0, 0, 0, 0, &res);

	if (result_count >= MAX_RESULTS)
		return;

	r = &results[result_count++];
	r->fid = fid;
	r->a0 = res.a0;
	r->a1 = res.a1;
	r->a2 = res.a2;
	r->a3 = res.a3;
}

/* /proc/rodin_smc_probe/single — single SMC */
static ssize_t single_write(struct file *f, const char __user *ub,
			    size_t n, loff_t *o)
{
	char buf[32];
	u32 fid;

	if (!n || n >= sizeof(buf))
		return -EINVAL;
	if (copy_from_user(buf, ub, n))
		return -EFAULT;
	buf[n] = '\0';
	if (kstrtouint(strim(buf), 0, &fid))
		return -EINVAL;

	mutex_lock(&probe_lock);
	do_smc(fid);
	mutex_unlock(&probe_lock);

	pr_info("rodin_smc_probe: single fid=0x%08x a0=0x%llx\n",
		fid, results[result_count-1].a0);
	return n;
}

static int single_show(struct seq_file *m, void *v)
{
	seq_puts(m, "write: \"<hex_fid>\" (e.g. 0x82000000)\n");
	seq_printf(m, "results captured: %d\n", result_count);
	return 0;
}

static int probe_single_open(struct inode *i, struct file *f)
{
	return single_open(f, single_show, NULL);
}

static const struct proc_ops single_ops = {
	.proc_open = probe_single_open, .proc_read = seq_read,
	.proc_lseek = seq_lseek, .proc_release = single_release,
	.proc_write = single_write,
};

/* /proc/rodin_smc_probe/range — scan range */
static ssize_t range_write(struct file *f, const char __user *ub,
			   size_t n, loff_t *o)
{
	char buf[64];
	u32 start, end, fid;
	int scanned = 0;

	if (!n || n >= sizeof(buf))
		return -EINVAL;
	if (copy_from_user(buf, ub, n))
		return -EFAULT;
	buf[n] = '\0';
	if (sscanf(buf, "%x %x", &start, &end) != 2)
		return -EINVAL;
	if (end < start || end - start > 2048)
		return -EINVAL;

	mutex_lock(&probe_lock);
	result_count = 0;
	for (fid = start; fid <= end && fid >= start; fid++) {
		do_smc(fid);
		scanned++;
		/* small delay every 16 iterations to avoid hogging */
		if ((scanned & 0xF) == 0)
			cond_resched();
	}
	mutex_unlock(&probe_lock);

	pr_info("rodin_smc_probe: scanned 0x%x..0x%x (%d FIDs)\n",
		start, end, scanned);
	return n;
}

static int range_show(struct seq_file *m, void *v)
{
	seq_puts(m, "write: \"<start_hex> <end_hex>\" (max 2048 range)\n");
	return 0;
}

static int probe_range_open(struct inode *i, struct file *f)
{
	return single_open(f, range_show, NULL);
}

static const struct proc_ops range_ops = {
	.proc_open = probe_range_open, .proc_read = seq_read,
	.proc_lseek = seq_lseek, .proc_release = single_release,
	.proc_write = range_write,
};

/* /proc/rodin_smc_probe/result — show all results */
static int result_show(struct seq_file *m, void *v)
{
	int i, valid = 0;

	seq_printf(m, "total results: %d\n", result_count);
	seq_puts(m, "fid          a0                  a1                  a2                  a3                  notes\n");
	for (i = 0; i < result_count; i++) {
		struct probe_result *r = &results[i];
		u32 lo32 = (u32)r->a0;
		const char *note = "";

		if (lo32 == SMC_UNKNOWN_LOW32)
			note = "UNKNOWN";
		else {
			note = "EXISTS!";
			valid++;
		}
		seq_printf(m, "0x%08x   0x%016llx  0x%016llx  0x%016llx  0x%016llx  %s\n",
			r->fid, r->a0, r->a1, r->a2, r->a3, note);
	}
	seq_printf(m, "\nValid (non-UNKNOWN): %d\n", valid);
	return 0;
}

static int probe_result_open(struct inode *i, struct file *f)
{
	return single_open(f, result_show, NULL);
}

static const struct proc_ops result_ops = {
	.proc_open = probe_result_open, .proc_read = seq_read,
	.proc_lseek = seq_lseek, .proc_release = single_release,
};

/* /proc/rodin_smc_probe/call — full SMC call with custom args */
static u64 last_call_fid, last_call_a0, last_call_a1, last_call_a2, last_call_a3;

static ssize_t call_write(struct file *f, const char __user *ub,
			  size_t n, loff_t *o)
{
	char buf[128];
	u64 args[7] = {0};
	struct arm_smccc_res res = {0};

	if (!n || n >= sizeof(buf))
		return -EINVAL;
	if (copy_from_user(buf, ub, n))
		return -EFAULT;
	buf[n] = '\0';
	if (sscanf(buf, "%llx %llx %llx %llx %llx %llx %llx",
		   &args[0], &args[1], &args[2], &args[3],
		   &args[4], &args[5], &args[6]) < 1)
		return -EINVAL;

	arm_smccc_smc(args[0], args[1], args[2], args[3],
		      args[4], args[5], args[6], 0, &res);
	last_call_fid = args[0];
	last_call_a0 = res.a0;
	last_call_a1 = res.a1;
	last_call_a2 = res.a2;
	last_call_a3 = res.a3;
	pr_info("rodin_smc_probe: call fid=0x%llx a1=0x%llx a2=0x%llx → a0=0x%lx a1_out=0x%lx\n",
		args[0], args[1], args[2], res.a0, res.a1);
	return n;
}

static int call_show(struct seq_file *m, void *v)
{
	seq_printf(m, "Last call: fid=0x%llx\n", last_call_fid);
	seq_printf(m, "  a0 (return) = 0x%016llx\n", last_call_a0);
	seq_printf(m, "  a1          = 0x%016llx\n", last_call_a1);
	seq_printf(m, "  a2          = 0x%016llx\n", last_call_a2);
	seq_printf(m, "  a3          = 0x%016llx\n", last_call_a3);
	seq_puts(m, "\nWrite: \"<fid> [<a1>] [<a2>] [<a3>] [<a4>] [<a5>] [<a6>]\" all hex\n");
	return 0;
}

static int call_open(struct inode *i, struct file *f)
{
	return single_open(f, call_show, NULL);
}

static const struct proc_ops call_ops = {
	.proc_open = call_open, .proc_read = seq_read,
	.proc_lseek = seq_lseek, .proc_release = single_release,
	.proc_write = call_write,
};

static struct proc_dir_entry *probe_dir;

static int __init rodin_smc_probe_init(void)
{
	results = kcalloc(MAX_RESULTS, sizeof(*results), GFP_KERNEL);
	if (!results)
		return -ENOMEM;

	probe_dir = proc_mkdir("rodin_smc_probe", NULL);
	if (!probe_dir) {
		kfree(results);
		return -ENOMEM;
	}

	proc_create("single", 0664, probe_dir, &single_ops);
	proc_create("range",  0664, probe_dir, &range_ops);
	proc_create("result", 0444, probe_dir, &result_ops);
	proc_create("call",   0664, probe_dir, &call_ops);

	pr_info("rodin_smc_probe: ready, max_results=%d\n", MAX_RESULTS);
	return 0;
}

static void __exit rodin_smc_probe_exit(void)
{
	proc_remove(probe_dir);
	kfree(results);
}

module_init(rodin_smc_probe_init);
module_exit(rodin_smc_probe_exit);

MODULE_DESCRIPTION("rodin_smc_probe — SMC FID enumerator via arm_smccc_smc");
MODULE_AUTHOR("Kaua / Revenant");
MODULE_LICENSE("GPL v2");
