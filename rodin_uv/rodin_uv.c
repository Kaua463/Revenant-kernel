// SPDX-License-Identifier: GPL-2.0
/*
 * rodin_uv.c v2 — Real Vproc undervolt for MT6899 (POCO X7 Pro / Dimensity 8400).
 *
 * History
 * -------
 * v1 (kthread @ 10Hz, both Vproc + Vsram): regulator API confirmed callable;
 * Vsram race we WIN (MCUPM does not defend Vsram), Vproc race we LOSE (Vproc
 * read kept reverting to MCUPM's values between our writes). Vsram side-effect
 * was harmful (Vsram=650mV persisted after rmmod — required reboot to restore).
 *
 * v2 (this file): drop Vsram entirely (factory MCUPM manages it, our touch was
 * net-negative), replace 10Hz kthread with a kprobe on the AP cpufreq driver's
 * mtk_cpufreq_hw_target_index. Fires AFTER every DVFS write the AP makes, in
 * the same context — minimal latency between MCUPM's write and our override.
 * If kprobe-driven reapply still loses to MCUPM, the race is between MCUPM's
 * own (firmware-internal, non-AP-observable) writes and ours; switch to direct
 * SPMI writes via spmi_ext_register_writel in v3 (needs mt6319 register map).
 *
 * Vendor symbols used here are all GLOBAL T exports — strong externs, no GOT
 * relocs, no kallsyms trick (except for one local-static target, mtk_cpufreq_
 * hw_target_index, which we resolve via the kprobe-on-kallsyms_lookup_name
 * pattern that rodin_eem v4 validated).
 *
 * Safety
 * ------
 * - target_uv_prime is clamped to [UV_PRIME_MIN, UV_PRIME_MAX].
 * - enable=0 default; user must explicitly set target + enable.
 * - rmmod removes the kprobe; MCUPM regains full control immediately.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include <linux/regulator/consumer.h>
#include <linux/kprobes.h>
#include <linux/atomic.h>
#include <linux/err.h>

#define REG_VPROC_PRIME_NAME  "8_vbuck1"

#define UV_PRIME_MIN  500000U
#define UV_PRIME_MAX  1193750U

static struct regulator *prime_reg;

static unsigned int target_uv_prime;
static atomic_t enable_flag      = ATOMIC_INIT(0);
static atomic_t applied_count    = ATOMIC_INIT(0);
static atomic_t kprobe_hits      = ATOMIC_INIT(0);
static atomic_t last_observed_uv = ATOMIC_INIT(0);
static atomic_t last_set_result  = ATOMIC_INIT(0);

/* kallsyms_lookup_name resolved via kprobe trick (the lookup itself is not
 * exported, but its address can be retrieved by registering a kprobe on it). */
typedef unsigned long (*kln_t)(const char *name);
static kln_t kln_fn;

static struct kprobe dvfs_kp;
static bool dvfs_kp_installed;

static int dvfs_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
	return 0;
}

static void dvfs_post_handler(struct kprobe *p, struct pt_regs *regs,
			      unsigned long flags)
{
	int ret, new_v;

	atomic_inc(&kprobe_hits);

	if (!atomic_read(&enable_flag) || !target_uv_prime || !prime_reg)
		return;

	ret = regulator_set_voltage(prime_reg, target_uv_prime, target_uv_prime);
	atomic_set(&last_set_result, ret);
	if (!ret) {
		atomic_inc(&applied_count);
		new_v = regulator_get_voltage(prime_reg);
		if (new_v > 0)
			atomic_set(&last_observed_uv, new_v);
	}
}

static int resolve_kln(void)
{
	struct kprobe k = {.symbol_name = "kallsyms_lookup_name"};
	int ret;

	ret = register_kprobe(&k);
	if (ret < 0) {
		pr_err("rodin_uv: kprobe on kallsyms_lookup_name failed: %d\n", ret);
		return ret;
	}
	kln_fn = (kln_t)k.addr;
	unregister_kprobe(&k);
	return 0;
}

static int install_dvfs_kprobe(void)
{
	unsigned long addr;
	int ret;

	if (!kln_fn)
		return -ENOSYS;
	addr = kln_fn("mtk_cpufreq_hw_target_index");
	if (!addr) {
		pr_err("rodin_uv: mtk_cpufreq_hw_target_index not found in kallsyms\n");
		return -ENOENT;
	}
	memset(&dvfs_kp, 0, sizeof(dvfs_kp));
	dvfs_kp.addr = (kprobe_opcode_t *)addr;
	dvfs_kp.pre_handler = dvfs_pre_handler;
	dvfs_kp.post_handler = dvfs_post_handler;
	ret = register_kprobe(&dvfs_kp);
	if (ret) {
		pr_err("rodin_uv: register_kprobe(dvfs) failed: %d\n", ret);
		return ret;
	}
	dvfs_kp_installed = true;
	pr_info("rodin_uv: kprobe installed @ mtk_cpufreq_hw_target_index = %lx\n",
		addr);
	return 0;
}

/* ---- /proc/rodin_uv/target_uv_prime ---- */
static int target_show(struct seq_file *m, void *v)
{
	seq_printf(m, "%u\n", target_uv_prime);
	return 0;
}

static ssize_t target_write(struct file *f, const char __user *ub,
			    size_t n, loff_t *o)
{
	char buf[32];
	unsigned int val;

	if (!n || n >= sizeof(buf))
		return -EINVAL;
	if (copy_from_user(buf, ub, n))
		return -EFAULT;
	buf[n] = '\0';
	if (kstrtouint(strim(buf), 0, &val))
		return -EINVAL;
	if (val != 0 && (val < UV_PRIME_MIN || val > UV_PRIME_MAX))
		return -EINVAL;
	target_uv_prime = val;
	return n;
}

/* ---- /proc/rodin_uv/enable ---- */
static int enable_show(struct seq_file *m, void *v)
{
	seq_printf(m, "%d\n", atomic_read(&enable_flag));
	return 0;
}

static ssize_t enable_write(struct file *f, const char __user *ub,
			    size_t n, loff_t *o)
{
	char buf[16];
	int val;

	if (!n || n >= sizeof(buf))
		return -EINVAL;
	if (copy_from_user(buf, ub, n))
		return -EFAULT;
	buf[n] = '\0';
	if (kstrtoint(strim(buf), 0, &val))
		return -EINVAL;
	atomic_set(&enable_flag, !!val);
	return n;
}

/* ---- /proc/rodin_uv/stats ---- */
static int stats_show(struct seq_file *m, void *v)
{
	int cur = prime_reg ? regulator_get_voltage(prime_reg) : -1;

	seq_printf(m,
		   "target_uv_prime:  %u\n"
		   "enable:           %d\n"
		   "kprobe_installed: %d\n"
		   "kprobe_hits:      %d\n"
		   "applied_count:    %d\n"
		   "last_observed_uv: %d\n"
		   "last_set_result:  %d\n"
		   "prime_reg:        %s\n"
		   "cur_proc_uv:      %d\n",
		   target_uv_prime,
		   atomic_read(&enable_flag),
		   dvfs_kp_installed ? 1 : 0,
		   atomic_read(&kprobe_hits),
		   atomic_read(&applied_count),
		   atomic_read(&last_observed_uv),
		   atomic_read(&last_set_result),
		   prime_reg ? "OK" : "MISSING",
		   cur);
	return 0;
}

#define RODIN_UV_RW(nm)							\
static int nm##_open(struct inode *i, struct file *f)			\
{ return single_open(f, nm##_show, NULL); }				\
static const struct proc_ops nm##_ops = {				\
	.proc_open = nm##_open, .proc_read = seq_read,			\
	.proc_lseek = seq_lseek, .proc_release = single_release,	\
	.proc_write = nm##_write,					\
}
#define RODIN_UV_RO(nm)							\
static int nm##_open(struct inode *i, struct file *f)			\
{ return single_open(f, nm##_show, NULL); }				\
static const struct proc_ops nm##_ops = {				\
	.proc_open = nm##_open, .proc_read = seq_read,			\
	.proc_lseek = seq_lseek, .proc_release = single_release,	\
}

RODIN_UV_RW(target);
RODIN_UV_RW(enable);
RODIN_UV_RO(stats);

static struct proc_dir_entry *uv_dir;

static int __init rodin_uv_init(void)
{
	int err;

	prime_reg = regulator_get_optional(NULL, REG_VPROC_PRIME_NAME);
	if (IS_ERR(prime_reg)) {
		pr_err("rodin_uv: regulator_get_optional(\"%s\") = %ld\n",
		       REG_VPROC_PRIME_NAME, PTR_ERR(prime_reg));
		prime_reg = NULL;
	}

	err = resolve_kln();
	if (err) {
		pr_warn("rodin_uv: kallsyms_lookup_name unavailable (%d) — kprobe path off\n",
			err);
	} else {
		err = install_dvfs_kprobe();
		if (err) {
			pr_warn("rodin_uv: dvfs kprobe install failed (%d) — running without race-win\n",
				err);
		}
	}

	uv_dir = proc_mkdir("rodin_uv", NULL);
	if (!uv_dir) {
		pr_err("rodin_uv: proc_mkdir failed\n");
		if (dvfs_kp_installed)
			unregister_kprobe(&dvfs_kp);
		if (prime_reg)
			regulator_put(prime_reg);
		return -ENOMEM;
	}
	proc_create("target_uv_prime", 0664, uv_dir, &target_ops);
	proc_create("enable",          0664, uv_dir, &enable_ops);
	proc_create("stats",           0444, uv_dir, &stats_ops);

	pr_info("rodin_uv v2 ready: prime_reg=%s kprobe=%s /proc/rodin_uv/ created\n",
		prime_reg ? "OK" : "NULL",
		dvfs_kp_installed ? "ON" : "OFF");
	return 0;
}

static void __exit rodin_uv_exit(void)
{
	if (dvfs_kp_installed) {
		unregister_kprobe(&dvfs_kp);
		dvfs_kp_installed = false;
	}
	proc_remove(uv_dir);
	if (prime_reg)
		regulator_put(prime_reg);
}

module_init(rodin_uv_init);
module_exit(rodin_uv_exit);

MODULE_DESCRIPTION("Revenant rodin_uv v2 — Vproc undervolt for MT6899 via regulator API + kprobe on mtk_cpufreq_hw_target_index");
MODULE_AUTHOR("Kaua / Revenant");
MODULE_LICENSE("GPL v2");
