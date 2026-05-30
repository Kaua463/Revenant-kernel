// SPDX-License-Identifier: GPL-2.0
/*
 * rodin_eem.c — EEMSN CPU undervolt control for MT6899 (rodin), as a standalone
 * loadable module. Port of MediaTek's eem-dbg.c (not shipped in retail HyperOS).
 *
 * Mechanism: AP sends an IPI on CH_S_EEMSN(=7) to the MCUPM firmware, which owns
 * CPU DVFS voltage. IPI_EEMSN_SETCLAMP/OFFSET removes the EEM guard band ->
 * undervolt. The MCUPM clamps the final voltage at VMIN, so the offset is bounded
 * and safe: worst case = instability/reboot (recoverable via rmmod/reboot), NOT
 * silicon death (that needs overvolt / firmware mod).
 *
 * Standalone notes:
 *  - Self-contained: no MTK vendor headers (defs inlined below).
 *  - Vendor symbols are STRONG externs (NOT weak): a weak undefined symbol whose
 *    address is taken forces a GOT relocation (R_AARCH64_LD64_GOT_LO12_NC=312),
 *    which the arm64 module loader rejects ("unsupported RELA relocation: 312").
 *    Strong externs -> direct CALL26 (handled by the loader via module PLTs).
 *    They resolve at insmod from the vendor modules (mcupm/mtk_tinysys_ipi/mtk_em);
 *    "no symbol version" / CRC mismatch is downgraded by the load-anyway patch.
 *    Symbols CONFIRMED exported (device kallsyms): get_mcupm_ipidev [mcupm],
 *    mtk_ipi_send_compl + mtk_ipi_register [mtk_tinysys_ipi], and (v2) the voltage
 *    table getter mtk_get_eemsn_log [mtk_em].
 *  - MUST be a module (.ko) loaded POST-boot (vendor symbols load after boot).
 *
 * CPU banks only (EEMSN_DET_L/BL/B/CCI). GPU undervolt is a separate driver.
 *
 * v2: eem_cur_volt now reads back the real per-bank/OPP voltage table via
 * mtk_get_eemsn_log(). LAYOUT NOTE: the struct below is the open-source mt6895
 * (eem-dbg-v1.h) layout — the oppo mt6899 vendor tree was not available to diff
 * against. To stay robust to any layout drift the readback is self-validating
 * (prints num_freq_tbl per bank, stops at freq==0) and reports the undervolt as a
 * PMIC-CODE DELTA (orig-pmic), which is EXACT regardless of the abs mV base/step.
 * Absolute mV is an annotated ESTIMATE (6.25mV/step, 0.4V base). read-only: at
 * worst it prints wrong absolute numbers, never faults the device.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include <linux/delay.h>
#include <linux/types.h>

/* ---- constants (mt6899 6.6, confirmed in handoff) ---- */
#define CH_S_EEMSN		7	/* mcupm_ipi_id_6.6.h */
#define MBOX_SLOT_SIZE		4	/* bytes/slot; msg = 16B / 4 = 4 slots */
#define IPI_SEND_POLLING	2	/* mtk_tinysys_ipi.h (WAIT=1, POLLING=2) */
#define EEM_IPI_TIMEOUT_MS	2000

/* IPI command enum — order from eem-dbg-v1.h (mt6899/mt6895 identical) */
enum {
	IPI_EEMSN_SHARERAM_INIT,
	IPI_EEMSN_INIT,
	IPI_EEMSN_PROBE,
	IPI_EEMSN_INIT01,
	IPI_EEMSN_GET_EEM_VOLT,		/* 4 */
	IPI_EEMSN_INIT02,
	IPI_EEMSN_DEBUG_PROC_WRITE,	/* 6 */
	IPI_EEMSN_SEND_UPOWER_TBL_REF,
	IPI_EEMSN_CUR_VOLT_PROC_SHOW,
	IPI_EEMSN_DUMP_PROC_SHOW,
	IPI_EEMSN_AGING_DUMP_PROC_SHOW,
	IPI_EEMSN_OFFSET_PROC_WRITE,	/* 11 */
	IPI_EEMSN_SETCLAMP_PROC_WRITE,	/* 12 */
	IPI_EEMSN_SNAGING_PROC_WRITE,
	IPI_EEMSN_LOGEN_PROC_SHOW,
	IPI_EEMSN_LOGEN_PROC_WRITE,
	IPI_EEMSN_EN_PROC_SHOW,
	IPI_EEMSN_EN_PROC_WRITE,
	IPI_EEMSN_SNEN_PROC_SHOW,
	IPI_EEMSN_SNEN_PROC_WRITE,
	IPI_EEMSN_FAKE_SN_INIT_ISR,
	IPI_EEMSN_FORCE_SN_SENSING,
	IPI_EEMSN_PULL_DATA,
	IPI_EEMSN_FAKE_SN_SENSING_ISR,
	NR_EEMSN_IPI,
};

enum eemsn_det_id {
	EEMSN_DET_L = 0,	/* efficiency cluster */
	EEMSN_DET_BL,		/* perf */
	EEMSN_DET_B,		/* prime / DSU */
	EEMSN_DET_CCI,
	NR_EEMSN_DET,
};

struct eemsn_ipi_data {
	unsigned int cmd;
	union {
		struct {
			unsigned int arg[3];
		} data;
	} u;
};

/*
 * EEMSN log (voltage table) — open-source mt6895 layout (eem-dbg-v1.h). The
 * firmware (MCUPM) writes this shared struct; mtk_get_eemsn_log() returns it.
 * volt_tbl_* entries are raw PMIC codes (1 step = 6.25mV on MT63xx bucks).
 * NR_FREQ is the per-detector OPP slot count; if mt6899 firmware uses a different
 * value, det_log[1..] shift — the readback's num_freq_tbl + freq==0 stop guards
 * make that visible (det0 stays correct as it is first) instead of crashing.
 */
#define NR_FREQ 32

struct eemsn_log_det {
	unsigned int temp;
	unsigned short freq_tbl[NR_FREQ];
	unsigned char volt_tbl_pmic[NR_FREQ];	/* applied (post-offset) voltage */
	unsigned char volt_tbl_orig[NR_FREQ];	/* original (pre-offset) voltage  */
	unsigned char volt_tbl_init2[NR_FREQ];
	unsigned char num_freq_tbl;
	unsigned char lock;
	unsigned char features;
	s8 volt_clamp;
	s8 volt_offset;
	enum eemsn_det_id det_id;
};

struct eemsn_log {
	unsigned int eemsn_disable:8;
	unsigned int ctrl_aging_Enable:8;
	unsigned int sn_disable:8;
	unsigned int segCode:8;
	unsigned char init2_v_ready;
	unsigned char init_vboot_done;
	unsigned char lock;
	unsigned char eemsn_log_en;
	struct eemsn_log_det det_log[NR_EEMSN_DET];
};

/*
 * Vendor symbols. WEAK so modpost does not error on "undefined" (they are not in
 * the GKI Module.symvers — they belong to vendor modules resolved at insmod).
 * CRITICAL: only ever CALL these, never take their ADDRESS. A direct call to a
 * weak fn emits CALL26 (loader-OK via PLT); taking its address emits a GOT load
 * (R_AARCH64_LD64_GOT_LO12_NC=312) which the arm64 module loader rejects. The
 * CI gate (readelf | grep GOT) enforces this. Symbols are confirmed exported, so
 * they resolve at load (CRC/version mismatch handled by load-anyway).
 */
extern void *get_mcupm_ipidev(void) __attribute__((weak));
extern int mtk_ipi_send_compl(void *ipidev, int ch, int opt, void *data,
			      int len, unsigned int timeout) __attribute__((weak));
extern int mtk_ipi_register(void *ipidev, int ch, void *cb, void *prdata,
			    void *msg) __attribute__((weak));
extern struct eemsn_log *mtk_get_eemsn_log(void) __attribute__((weak));

static int ipi_ackdata;

/* send one command to MCUPM. returns ipi ret, or -ENODEV if ipidev not ready */
static int eem_to_up(unsigned int cmd, struct eemsn_ipi_data *eem_data)
{
	void *ipidev = get_mcupm_ipidev();

	if (!ipidev) {
		pr_warn("rodin_eem: get_mcupm_ipidev() returned NULL\n");
		return -ENODEV;
	}
	eem_data->cmd = cmd;
	return mtk_ipi_send_compl(ipidev, CH_S_EEMSN, IPI_SEND_POLLING, eem_data,
				 sizeof(struct eemsn_ipi_data) / MBOX_SLOT_SIZE,
				 EEM_IPI_TIMEOUT_MS);
}

/* parse "<bank_id 0..3> <value>" -> bank,val. returns 0 on success */
static int parse_bank_val(const char __user *ubuf, size_t count,
			  int *bank, int *val)
{
	char buf[64], *p, *tok;

	if (count == 0 || count >= sizeof(buf))
		return -EINVAL;
	if (copy_from_user(buf, ubuf, count))
		return -EFAULT;
	buf[count] = '\0';
	p = buf;

	tok = strsep(&p, " ");
	if (!tok || kstrtoint(tok, 10, bank))
		return -EINVAL;
	if (*bank < 0 || *bank >= NR_EEMSN_DET)
		return -EINVAL;
	if (!p || kstrtoint(strim(p), 10, val))
		return -EINVAL;
	return 0;
}

/* ---- /proc/eem/eem_setclamp (RW): "<bank_id> <volt_clamp>" ---- */
static int eem_setclamp_show(struct seq_file *m, void *v)
{
	seq_puts(m, "write: \"<bank_id 0..3> <volt_clamp>\" (clamp bounded at VMIN by MCUPM)\n");
	return 0;
}

static ssize_t eem_setclamp_write(struct file *f, const char __user *ubuf,
				  size_t count, loff_t *pos)
{
	struct eemsn_ipi_data eem_data;
	int bank = 0, clamp = 0, ret;

	ret = parse_bank_val(ubuf, count, &bank, &clamp);
	if (ret)
		return ret;

	memset(&eem_data, 0, sizeof(eem_data));
	eem_data.u.data.arg[0] = bank;
	eem_data.u.data.arg[1] = clamp;
	ret = eem_to_up(IPI_EEMSN_SETCLAMP_PROC_WRITE, &eem_data);
	pr_info("rodin_eem: setclamp bank=%d clamp=%d ipi_ret=%d\n",
		bank, clamp, ret);
	return count;
}

/* ---- /proc/eem/eem_offset (RW): "<bank_id> <offset>" ---- */
static int eem_offset_show(struct seq_file *m, void *v)
{
	seq_puts(m, "write: \"<bank_id 0..3> <offset>\"\n");
	return 0;
}

static ssize_t eem_offset_write(struct file *f, const char __user *ubuf,
				size_t count, loff_t *pos)
{
	struct eemsn_ipi_data eem_data;
	int bank = 0, offset = 0, ret;

	ret = parse_bank_val(ubuf, count, &bank, &offset);
	if (ret)
		return ret;

	memset(&eem_data, 0, sizeof(eem_data));
	eem_data.u.data.arg[0] = bank;
	eem_data.u.data.arg[1] = offset;
	ret = eem_to_up(IPI_EEMSN_OFFSET_PROC_WRITE, &eem_data);
	pr_info("rodin_eem: offset bank=%d offset=%d ipi_ret=%d\n",
		bank, offset, ret);
	return count;
}

/*
 * PMIC code -> microvolts. Standard MT63xx buck: 6.25mV/step, 0.4V floor. The
 * struct carries no step/base, so ABSOLUTE mV is an estimate; the orig-pmic code
 * DELTA is exact (both in the same unit). Calibrate base from a known anchor if
 * the abs numbers look off.
 */
#define EEM_PMIC_STEP_UV	6250
#define EEM_PMIC_BASE_UV	400000

static int eem_code_to_uv(unsigned char code)
{
	return (int)code * EEM_PMIC_STEP_UV + EEM_PMIC_BASE_UV;
}

/* print a signed microvolt value as "[-]N.NN" (millivolts, 2 decimals) */
static void eem_seq_mv(struct seq_file *m, int uv)
{
	int a = uv < 0 ? -uv : uv;

	seq_printf(m, "%s%d.%02d", uv < 0 ? "-" : "", a / 1000, (a % 1000) / 10);
}

static const char *const eem_det_name[NR_EEMSN_DET] = {
	"eff", "perf", "prime", "cci"
};

/* ---- /proc/eem/eem_cur_volt (RO): GET_EEM_VOLT then dump per-bank/OPP table ---- */
static int eem_cur_volt_show(struct seq_file *m, void *v)
{
	struct eemsn_ipi_data eem_data;
	struct eemsn_log *log;
	unsigned char lock;
	int ipi_ret, bank, i, lim = 0;

	/* refresh volt_tbl_pmic from MCUPM, then read the shared log */
	memset(&eem_data, 0, sizeof(eem_data));
	ipi_ret = eem_to_up(IPI_EEMSN_GET_EEM_VOLT, &eem_data);

	log = mtk_get_eemsn_log();
	if (!log) {
		seq_printf(m, "ipi_ret:%d\nmtk_get_eemsn_log() NULL — table unavailable\n",
			   ipi_ret);
		return 0;
	}

	/* mirror eem-dbg: wait out the firmware write lock before reading */
	do {
		lock = log->lock;
		mdelay(5);
		lock = log->lock;
	} while ((lock & 0x1) && (++lim < 5));

	seq_printf(m, "ipi_ret:%d  (abs mV = est @6.25mV/step,0.4V base; DELTA is exact)\n",
		   ipi_ret);

	for (bank = 0; bank < NR_EEMSN_DET; bank++) {
		struct eemsn_log_det *d = &log->det_log[bank];
		unsigned int n = d->num_freq_tbl;

		seq_printf(m, "det%d(%s) num_freq=%u clamp=%d offset=%d\n",
			   bank, eem_det_name[bank], n,
			   d->volt_clamp, d->volt_offset);
		if (n > NR_FREQ)		/* sanity bound vs layout drift */
			n = NR_FREQ;
		for (i = 0; i < (int)n; i++) {
			unsigned char orig = d->volt_tbl_orig[i];
			unsigned char pmic = d->volt_tbl_pmic[i];
			int delta_uv;

			if (d->freq_tbl[i] == 0)
				break;
			delta_uv = ((int)orig - (int)pmic) * EEM_PMIC_STEP_UV;

			seq_printf(m, "  opp%-2d freq=%-5hu orig=0x%02x(",
				   i, d->freq_tbl[i], orig);
			eem_seq_mv(m, eem_code_to_uv(orig));
			seq_printf(m, "mV) pmic=0x%02x(", pmic);
			eem_seq_mv(m, eem_code_to_uv(pmic));
			seq_puts(m, "mV) delta=");
			eem_seq_mv(m, delta_uv);
			seq_puts(m, "mV\n");
		}
	}
	return 0;
}

/* ---- /proc/eem/eem_debug (RW): "<bank_id> <disable>" — per-bank enable ---- */
static int eem_debug_show(struct seq_file *m, void *v)
{
	return 0;
}

static ssize_t eem_debug_write(struct file *f, const char __user *ubuf,
			       size_t count, loff_t *pos)
{
	struct eemsn_ipi_data eem_data;
	int bank = 0, disable = 0, ret;

	ret = parse_bank_val(ubuf, count, &bank, &disable);
	if (ret)
		return ret;

	memset(&eem_data, 0, sizeof(eem_data));
	eem_data.u.data.arg[0] = bank;
	eem_data.u.data.arg[1] = disable;
	eem_to_up(IPI_EEMSN_DEBUG_PROC_WRITE, &eem_data);
	return count;
}

/* ---- /proc/eem/eem_disable (RW): global EEMSN enable/disable ---- */
static int eem_disable_show(struct seq_file *m, void *v)
{
	seq_puts(m, "write an int to enable/disable EEMSN (EN_PROC_WRITE)\n");
	return 0;
}

static ssize_t eem_disable_write(struct file *f, const char __user *ubuf,
				 size_t count, loff_t *pos)
{
	char buf[32];
	struct eemsn_ipi_data eem_data;
	int val;

	if (count == 0 || count >= sizeof(buf))
		return -EINVAL;
	if (copy_from_user(buf, ubuf, count))
		return -EFAULT;
	buf[count] = '\0';
	if (kstrtoint(strim(buf), 10, &val))
		return -EINVAL;

	memset(&eem_data, 0, sizeof(eem_data));
	eem_data.u.data.arg[0] = val;
	eem_to_up(IPI_EEMSN_EN_PROC_WRITE, &eem_data);
	return count;
}

/* ---- proc_ops glue ---- */
#define EEM_RW(nm)							\
static int nm##_open(struct inode *i, struct file *f)			\
{ return single_open(f, nm##_show, NULL); }				\
static const struct proc_ops nm##_ops = {				\
	.proc_open = nm##_open, .proc_read = seq_read,			\
	.proc_lseek = seq_lseek, .proc_release = single_release,	\
	.proc_write = nm##_write,					\
}
#define EEM_RO(nm)							\
static int nm##_open(struct inode *i, struct file *f)			\
{ return single_open(f, nm##_show, NULL); }				\
static const struct proc_ops nm##_ops = {				\
	.proc_open = nm##_open, .proc_read = seq_read,			\
	.proc_lseek = seq_lseek, .proc_release = single_release,	\
}

EEM_RW(eem_setclamp);
EEM_RW(eem_offset);
EEM_RO(eem_cur_volt);
EEM_RW(eem_debug);
EEM_RW(eem_disable);

static struct proc_dir_entry *eem_dir;

static int __init rodin_eem_init(void)
{
	void *ipidev;
	int err;

	/* register the AP side of CH_S_EEMSN (eem-dbg normally does this) */
	ipidev = get_mcupm_ipidev();
	if (ipidev) {
		err = mtk_ipi_register(ipidev, CH_S_EEMSN, NULL, NULL,
				       &ipi_ackdata);
		if (err)
			pr_info("rodin_eem: ipi_register ret=%d (maybe already registered)\n",
				err);
	} else {
		pr_warn("rodin_eem: get_mcupm_ipidev() NULL at init (mcupm not ready?)\n");
	}

	eem_dir = proc_mkdir("eem", NULL);
	if (!eem_dir) {
		pr_err("rodin_eem: failed to create /proc/eem\n");
		return -ENOMEM;
	}
	proc_create("eem_setclamp", 0664, eem_dir, &eem_setclamp_ops);
	proc_create("eem_offset",   0664, eem_dir, &eem_offset_ops);
	proc_create("eem_cur_volt", 0444, eem_dir, &eem_cur_volt_ops);
	proc_create("eem_debug",    0664, eem_dir, &eem_debug_ops);
	proc_create("eem_disable",  0664, eem_dir, &eem_disable_ops);

	pr_info("rodin_eem: /proc/eem ready (ipidev=%p)\n", ipidev);
	return 0;
}

static void __exit rodin_eem_exit(void)
{
	proc_remove(eem_dir);
}

module_init(rodin_eem_init);
module_exit(rodin_eem_exit);

MODULE_DESCRIPTION("Revenant EEMSN CPU undervolt (rodin/MT6899) — eem-dbg port");
MODULE_AUTHOR("Kaua / Revenant");
MODULE_LICENSE("GPL v2");
