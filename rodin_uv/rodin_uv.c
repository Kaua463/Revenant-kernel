// SPDX-License-Identifier: GPL-2.0
/*
 * rodin_uv.c — Real Vproc/Vsram undervolt for MT6899 (POCO X7 Pro / Dimensity 8400).
 *
 * Premise (validated on-device 2026-05-30):
 *  - /proc/eem (EEMSN setclamp + eem_offset) is admin-only at the silicon level.
 *    The eemsn_log struct mirrors the firmware view but writing to it does NOT
 *    change the actual PMIC voltage. Proven by current draw measurement:
 *    baseline -1477mA, offset -96 (table says 550mV @ 3.25GHz prime) -1475mA,
 *    device 100% stable. If -650mV undervolt were real, A725 would die instantly.
 *
 *  - The REAL undervolt path is regulator_set_voltage. It IS exported in this
 *    kernel (uppercase T in kallsyms). Calling it from a module triggers the
 *    mt6319 driver's set_voltage_sel callback, which writes the buck control
 *    register via SPMI bus. PMIC output really changes.
 *
 *  - cpufreq-hw (mtk-cpufreq-hw) bypasses the regulator framework: MCUPM owns
 *    DVFS and writes the PMIC directly over its own SPMI channel. So after AP
 *    writes our undervolt value, MCUPM will overwrite on the next DVFS event.
 *    DVFS rate measured under load: PRIME = 2 transitions/s. Trivially winnable.
 *
 *  - This module wakes a kthread @ 10Hz and re-applies our target voltage on
 *    Vproc_prime + Vsram_cpub. Between MCUPM's writes (~2/s) our writes (~10/s)
 *    dominate: ~5 reapplications per MCUPM clobber.
 *
 * Vsram-Vproc constraint (also validated on-device 2026-05-30):
 *  - Reading 8_vbuck1=793750 mt6363_vsram_cpub=743750 under load => Vsram lies
 *    ~50mV BELOW Vproc. INVERSE of the mtk-cci-devfreq pattern. We keep this
 *    direction so the silicon stays in its operating envelope.
 *  - Ordering: lowering Vproc -> drop Vsram first, then Vproc.
 *              raising Vproc  -> raise Vproc first, then Vsram.
 *
 * Safety:
 *  - Hard floor: 500000 uV (A725 cannot switch reliably below ~500mV).
 *  - enable=0 by default; user must explicitly set target_uv_prime and enable=1.
 *  - rmmod stops the kthread; regulator framework restores the last AP-known
 *    voltage, MCUPM resumes full control.
 *
 * Module layout follows rodin_eem (same build pipeline, same vermagic flow).
 * Vendor symbols are GLOBAL T (exported), so we use STRONG externs — no GOT
 * relocs, no kallsyms trick needed.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include <linux/regulator/consumer.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/atomic.h>
#include <linux/err.h>

/* Supply names — exactly as seen in /sys/class/regulator/regulator.N/name on
 * the rodin device. regulator_get_optional(NULL, name) finds the rdev by its
 * constraint_name in the global regulator list. */
#define REG_VPROC_PRIME_NAME  "8_vbuck1"            /* mt6319-8 / regulator.11 */
#define REG_VSRAM_CPUB_NAME   "mt6363_vsram_cpub"   /* regulator.30 */

/* Hard floor / ceiling in microvolts. mt6319-8 buck constraint is 300000..1193750. */
#define UV_PRIME_MIN  500000U
#define UV_PRIME_MAX  1193750U

/* Vsram lies ~50mV BELOW Vproc on rodin (inverse of upstream MTK pattern). */
#define VSRAM_DELTA_FROM_PROC  (-50000)

/* kthread reapply period. 100ms = 10Hz, > 4x the measured DVFS rate (2/s). */
#define REAPPLY_PERIOD_MS  100

static struct regulator *prime_reg;
static struct regulator *vsram_reg;

static unsigned int target_uv_prime;   /* 0 == disabled / no-op */
static atomic_t enable_flag      = ATOMIC_INIT(0);
static atomic_t applied_count    = ATOMIC_INIT(0);
static atomic_t last_observed_uv = ATOMIC_INIT(0);
static atomic_t last_set_result  = ATOMIC_INIT(0);

static struct task_struct *uv_kth;

static struct regulator *try_get(const char *name)
{
	struct regulator *r;

	r = regulator_get_optional(NULL, name);
	if (!IS_ERR(r))
		return r;

	pr_info("rodin_uv: regulator_get_optional(NULL, \"%s\") -> %ld\n",
		name, PTR_ERR(r));
	return NULL;
}

static int apply_target(unsigned int uv)
{
	int ret, cur_proc, new_v;
	unsigned int vsram_uv;

	if (!prime_reg || !vsram_reg)
		return -ENODEV;
	if (uv < UV_PRIME_MIN || uv > UV_PRIME_MAX)
		return -EINVAL;

	vsram_uv = (unsigned int)((int)uv + VSRAM_DELTA_FROM_PROC);

	cur_proc = regulator_get_voltage(prime_reg);
	if (cur_proc < 0)
		cur_proc = 0;

	if ((int)uv <= cur_proc) {
		/* lowering: Vsram first (keeps Vsram <= Vproc throughout), then Vproc */
		ret = regulator_set_voltage(vsram_reg, vsram_uv, vsram_uv);
		if (ret)
			return ret;
		ret = regulator_set_voltage(prime_reg, uv, uv);
		if (ret)
			return ret;
	} else {
		/* raising: Vproc first, then Vsram catches up */
		ret = regulator_set_voltage(prime_reg, uv, uv);
		if (ret)
			return ret;
		ret = regulator_set_voltage(vsram_reg, vsram_uv, vsram_uv);
		if (ret)
			return ret;
	}

	atomic_inc(&applied_count);
	new_v = regulator_get_voltage(prime_reg);
	if (new_v > 0)
		atomic_set(&last_observed_uv, new_v);
	return 0;
}

static int rodin_uv_thread(void *data)
{
	while (!kthread_should_stop()) {
		if (atomic_read(&enable_flag) && target_uv_prime) {
			int r = apply_target(target_uv_prime);

			atomic_set(&last_set_result, r);
		}
		msleep_interruptible(REAPPLY_PERIOD_MS);
	}
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

/* ---- /proc/rodin_uv/stats (read-only summary) ---- */
static int stats_show(struct seq_file *m, void *v)
{
	int cur_proc = prime_reg ? regulator_get_voltage(prime_reg) : -1;
	int cur_vsram = vsram_reg ? regulator_get_voltage(vsram_reg) : -1;

	seq_printf(m,
		   "target_uv_prime:  %u\n"
		   "enable:           %d\n"
		   "applied_count:    %d\n"
		   "last_observed_uv: %d\n"
		   "last_set_result:  %d\n"
		   "prime_reg:        %s\n"
		   "vsram_reg:        %s\n"
		   "cur_proc_uv:      %d\n"
		   "cur_vsram_uv:     %d\n"
		   "reapply_period_ms:%d\n",
		   target_uv_prime,
		   atomic_read(&enable_flag),
		   atomic_read(&applied_count),
		   atomic_read(&last_observed_uv),
		   atomic_read(&last_set_result),
		   prime_reg ? "OK" : "MISSING",
		   vsram_reg ? "OK" : "MISSING",
		   cur_proc,
		   cur_vsram,
		   REAPPLY_PERIOD_MS);
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
	prime_reg = try_get(REG_VPROC_PRIME_NAME);
	vsram_reg = try_get(REG_VSRAM_CPUB_NAME);

	uv_dir = proc_mkdir("rodin_uv", NULL);
	if (!uv_dir) {
		pr_err("rodin_uv: proc_mkdir failed\n");
		goto err_proc;
	}
	proc_create("target_uv_prime", 0664, uv_dir, &target_ops);
	proc_create("enable",          0664, uv_dir, &enable_ops);
	proc_create("stats",           0444, uv_dir, &stats_ops);

	uv_kth = kthread_run(rodin_uv_thread, NULL, "rodin_uv");
	if (IS_ERR(uv_kth)) {
		pr_err("rodin_uv: kthread_run failed: %ld\n", PTR_ERR(uv_kth));
		uv_kth = NULL;
	}

	pr_info("rodin_uv: ready (prime_reg=%s vsram_reg=%s); /proc/rodin_uv/ created\n",
		prime_reg ? "OK" : "NULL", vsram_reg ? "OK" : "NULL");
	return 0;

err_proc:
	if (prime_reg)
		regulator_put(prime_reg);
	if (vsram_reg)
		regulator_put(vsram_reg);
	return -ENOMEM;
}

static void __exit rodin_uv_exit(void)
{
	if (uv_kth)
		kthread_stop(uv_kth);
	proc_remove(uv_dir);
	if (prime_reg)
		regulator_put(prime_reg);
	if (vsram_reg)
		regulator_put(vsram_reg);
}

module_init(rodin_uv_init);
module_exit(rodin_uv_exit);

MODULE_DESCRIPTION("Revenant rodin_uv — real Vproc/Vsram undervolt for MT6899 via regulator API + kthread race");
MODULE_AUTHOR("Kaua / Revenant");
MODULE_LICENSE("GPL v2");
