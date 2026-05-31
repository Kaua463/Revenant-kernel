// SPDX-License-Identifier: GPL-2.0
/*
 * rodin_uv.c v3 — Real Vproc undervolt for MT6899 (POCO X7 Pro / Dimensity 8400).
 *
 * History
 * -------
 * v1 (10Hz kthread on Vproc + Vsram): regulator API confirmed callable; Vsram
 *   race won (lower Vsram persisted post-rmmod, harmful), Vproc race lost.
 * v2 (kprobe on mtk_cpufreq_hw_target_index, Vproc-only): kprobe registered
 *   successfully but kprobe_hits stayed at 0 even with DVFS clearly active.
 *   Reason: rodin uses governor 'sugov_ext' (Xiaomi-extended schedutil) which
 *   calls cpufreq_driver_fast_switch -> mtk_cpufreq_hw_fast_switch. The
 *   target_index path is unused in this configuration.
 *
 * v3 (this file):
 *   - kprobe BOTH fast_switch (primary) and target_index (fallback for any
 *     governor that doesn't use fast_switch).
 *   - fast_switch is called from the scheduler in a possibly-atomic context;
 *     regulator_set_voltage may sleep (mutex_lock). So the post_handler does
 *     NOT call regulator directly — it schedules a work item on a dedicated
 *     unbound workqueue. The work runs in process context, sleep-safe.
 *   - Workqueue latency (~us-to-ms) is fine: MCUPM writes Vproc shortly after
 *     fast_switch dispatches the DVFS request to it; our work running after
 *     that lands AFTER MCUPM's write, which is exactly what wins the race.
 *
 * Future
 * ------
 * If kprobe fires but Vproc still doesn't track target: fall back to direct
 * SPMI writes via spmi_ext_register_writel on mt6319 (slave 8). Needs the
 * mt6319 VBUCK1_VOL_CTRL register offset (not in /proc, would need RE).
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
#include <linux/workqueue.h>
#include <linux/atomic.h>
#include <linux/err.h>

#define REG_VPROC_PRIME_NAME  "8_vbuck1"

#define UV_PRIME_MIN  500000U
#define UV_PRIME_MAX  1193750U

static struct regulator *prime_reg;

static unsigned int target_uv_prime;
static atomic_t enable_flag      = ATOMIC_INIT(0);
static atomic_t applied_count    = ATOMIC_INIT(0);
static atomic_t kp_hit_fastsw    = ATOMIC_INIT(0);
static atomic_t kp_hit_target    = ATOMIC_INIT(0);
static atomic_t work_runs        = ATOMIC_INIT(0);
static atomic_t last_observed_uv = ATOMIC_INIT(0);
static atomic_t last_set_result  = ATOMIC_INIT(0);

typedef unsigned long (*kln_t)(const char *name);
static kln_t kln_fn;

static struct kprobe kp_fastsw;
static struct kprobe kp_target;
static bool kp_fastsw_installed;
static bool kp_target_installed;

static struct workqueue_struct *uv_wq;
static struct work_struct apply_work;

/* Workqueue handler — runs in process context, sleep-safe for regulator API */
static void apply_work_fn(struct work_struct *w)
{
	int ret, new_v;

	atomic_inc(&work_runs);

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

/* kprobe post handlers — fast, atomic-safe; queue the real work */
static int kp_noop_pre(struct kprobe *p, struct pt_regs *regs)
{
	return 0;
}

static void kp_post_fastsw(struct kprobe *p, struct pt_regs *regs,
			   unsigned long flags)
{
	atomic_inc(&kp_hit_fastsw);
	if (atomic_read(&enable_flag) && target_uv_prime && uv_wq)
		queue_work(uv_wq, &apply_work);
}

static void kp_post_target(struct kprobe *p, struct pt_regs *regs,
			   unsigned long flags)
{
	atomic_inc(&kp_hit_target);
	if (atomic_read(&enable_flag) && target_uv_prime && uv_wq)
		queue_work(uv_wq, &apply_work);
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

static int install_one(struct kprobe *kp, const char *name,
		       kprobe_post_handler_t post, bool *flag)
{
	unsigned long addr;
	int ret;

	if (!kln_fn)
		return -ENOSYS;
	addr = kln_fn(name);
	if (!addr) {
		pr_warn("rodin_uv: %s not in kallsyms\n", name);
		return -ENOENT;
	}
	memset(kp, 0, sizeof(*kp));
	kp->addr = (kprobe_opcode_t *)addr;
	kp->pre_handler = kp_noop_pre;
	kp->post_handler = post;
	ret = register_kprobe(kp);
	if (ret) {
		pr_warn("rodin_uv: register_kprobe(%s) failed: %d\n", name, ret);
		return ret;
	}
	*flag = true;
	pr_info("rodin_uv: kprobe ON %s @ %lx\n", name, addr);
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
		   "target_uv_prime:   %u\n"
		   "enable:            %d\n"
		   "kp_fastsw_on:      %d\n"
		   "kp_target_on:      %d\n"
		   "kp_hit_fastsw:     %d\n"
		   "kp_hit_target:     %d\n"
		   "work_runs:         %d\n"
		   "applied_count:     %d\n"
		   "last_observed_uv:  %d\n"
		   "last_set_result:   %d\n"
		   "prime_reg:         %s\n"
		   "cur_proc_uv:       %d\n",
		   target_uv_prime,
		   atomic_read(&enable_flag),
		   kp_fastsw_installed ? 1 : 0,
		   kp_target_installed ? 1 : 0,
		   atomic_read(&kp_hit_fastsw),
		   atomic_read(&kp_hit_target),
		   atomic_read(&work_runs),
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

	uv_wq = alloc_workqueue("rodin_uv", WQ_UNBOUND | WQ_HIGHPRI, 0);
	if (!uv_wq) {
		pr_err("rodin_uv: alloc_workqueue failed\n");
		if (prime_reg)
			regulator_put(prime_reg);
		return -ENOMEM;
	}
	INIT_WORK(&apply_work, apply_work_fn);

	err = resolve_kln();
	if (err) {
		pr_warn("rodin_uv: kallsyms_lookup_name unavailable (%d) — kprobes off\n",
			err);
	} else {
		install_one(&kp_fastsw, "mtk_cpufreq_hw_fast_switch",
			    kp_post_fastsw, &kp_fastsw_installed);
		install_one(&kp_target, "mtk_cpufreq_hw_target_index",
			    kp_post_target, &kp_target_installed);
	}

	uv_dir = proc_mkdir("rodin_uv", NULL);
	if (!uv_dir) {
		pr_err("rodin_uv: proc_mkdir failed\n");
		if (kp_fastsw_installed)
			unregister_kprobe(&kp_fastsw);
		if (kp_target_installed)
			unregister_kprobe(&kp_target);
		destroy_workqueue(uv_wq);
		if (prime_reg)
			regulator_put(prime_reg);
		return -ENOMEM;
	}
	proc_create("target_uv_prime", 0664, uv_dir, &target_ops);
	proc_create("enable",          0664, uv_dir, &enable_ops);
	proc_create("stats",           0444, uv_dir, &stats_ops);

	pr_info("rodin_uv v3 ready: prime_reg=%s kp_fastsw=%s kp_target=%s /proc/rodin_uv/ created\n",
		prime_reg ? "OK" : "NULL",
		kp_fastsw_installed ? "ON" : "OFF",
		kp_target_installed ? "ON" : "OFF");
	return 0;
}

static void __exit rodin_uv_exit(void)
{
	atomic_set(&enable_flag, 0);
	if (kp_fastsw_installed) {
		unregister_kprobe(&kp_fastsw);
		kp_fastsw_installed = false;
	}
	if (kp_target_installed) {
		unregister_kprobe(&kp_target);
		kp_target_installed = false;
	}
	if (uv_wq) {
		flush_workqueue(uv_wq);
		destroy_workqueue(uv_wq);
		uv_wq = NULL;
	}
	proc_remove(uv_dir);
	if (prime_reg)
		regulator_put(prime_reg);
}

module_init(rodin_uv_init);
module_exit(rodin_uv_exit);

MODULE_DESCRIPTION("Revenant rodin_uv v3 — Vproc undervolt for MT6899 via regulator API + kprobe on fast_switch/target_index + workqueue");
MODULE_AUTHOR("Kaua / Revenant");
MODULE_LICENSE("GPL v2");
