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
 *  - Self-contained: no MTK vendor headers needed (defs inlined below).
 *  - Vendor symbols are WEAK externs (get_mcupm_ipidev/mtk_ipi_send_compl/
 *    mtk_ipi_register from mcupm+mtk_tinysys_ipi; mtk_get_eemsn_log from mtk_em).
 *    Weak => the module ALWAYS loads even if a symbol is absent; each op NULL-checks
 *    and reports. CRC mismatch on resolve is handled by the load-anyway patch.
 *  - MUST be a module (.ko) loaded POST-boot: the vendor symbols come from vendor
 *    modules that load after boot; built-in would not resolve them.
 *
 * CPU banks only (EEMSN_DET_L/BL/B/CCI). GPU undervolt is a separate driver.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include <linux/delay.h>
#include <linux/string.h>

/* ---- constants (mt6899 6.6, confirmed in handoff) ---- */
#define CH_S_EEMSN		7	/* mcupm_ipi_id_6.6.h */
#define MBOX_SLOT_SIZE		4	/* bytes/slot; msg = 16B / 4 = 4 slots */
#define IPI_SEND_POLLING	2	/* mtk_tinysys_ipi.h (WAIT=1, POLLING=2) */
#define EEM_IPI_TIMEOUT_MS	2000

#define NR_FREQ			32

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

struct eemsn_log_det {
	unsigned int temp;
	unsigned short freq_tbl[NR_FREQ];
	unsigned char volt_tbl_pmic[NR_FREQ];
	unsigned char volt_tbl_orig[NR_FREQ];
	unsigned char volt_tbl_init2[NR_FREQ];
	unsigned char num_freq_tbl;
	unsigned char lock;
	unsigned char features;
	signed char volt_clamp;
	signed char volt_offset;
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

/* ---- vendor symbols (weak; resolve at insmod from vendor modules) ---- */
extern void *get_mcupm_ipidev(void) __attribute__((weak));
extern int mtk_ipi_send_compl(void *ipidev, int ch, int opt, void *data,
			      int len, unsigned int timeout) __attribute__((weak));
extern int mtk_ipi_register(void *ipidev, int ch, void *cb, void *prdata,
			    void *msg) __attribute__((weak));
extern struct eemsn_log *mtk_get_eemsn_log(void) __attribute__((weak));

static struct eemsn_log *eemsn_log;
static int ipi_ackdata;
static bool ipi_registered;

static struct eemsn_log *eem_get_log(void)
{
	if (!eemsn_log && mtk_get_eemsn_log)
		eemsn_log = mtk_get_eemsn_log();
	return eemsn_log;
}

/* send one command to MCUPM. returns ipi ret, or negative if unavailable */
static int eem_to_up(unsigned int cmd, struct eemsn_ipi_data *eem_data)
{
	void *ipidev;

	if (!get_mcupm_ipidev || !mtk_ipi_send_compl) {
		pr_warn("rodin_eem: mcupm IPI symbols unresolved (vendor modules loaded?)\n");
		return -ENODEV;
	}
	ipidev = get_mcupm_ipidev();
	if (!ipidev) {
		pr_warn("rodin_eem: get_mcupm_ipidev() returned NULL\n");
		return -ENODEV;
	}

	eem_data->cmd = cmd;
	return mtk_ipi_send_compl(ipidev, CH_S_EEMSN, IPI_SEND_POLLING, eem_data,
				 sizeof(struct eemsn_ipi_data) / MBOX_SLOT_SIZE,
				 EEM_IPI_TIMEOUT_MS);
}

/* ---- /proc/eem/setclamp (RW): "<bank_id> <volt_clamp>" ---- */
static int eem_setclamp_show(struct seq_file *m, void *v)
{
	seq_puts(m, "write: \"<bank_id 0..3> <volt_clamp>\" (clamp bounded at VMIN by MCUPM)\n");
	return 0;
}

static ssize_t eem_setclamp_write(struct file *f, const char __user *ubuf,
				  size_t count, loff_t *pos)
{
	char buf[64], *p, *tok;
	struct eemsn_ipi_data eem_data;
	int bank_id = 0, volt_clamp = 0, ret;

	if (count == 0 || count >= sizeof(buf))
		return -EINVAL;
	if (copy_from_user(buf, ubuf, count))
		return -EFAULT;
	buf[count] = '\0';
	p = buf;

	tok = strsep(&p, " ");
	if (!tok || kstrtoint(tok, 10, &bank_id))
		return -EINVAL;
	if (bank_id < 0 || bank_id >= NR_EEMSN_DET)
		return -EINVAL;
	if (!p || kstrtoint(strim(p), 10, &volt_clamp))
		return -EINVAL;

	memset(&eem_data, 0, sizeof(eem_data));
	eem_data.u.data.arg[0] = bank_id;
	eem_data.u.data.arg[1] = volt_clamp;
	ret = eem_to_up(IPI_EEMSN_SETCLAMP_PROC_WRITE, &eem_data);
	pr_info("rodin_eem: setclamp bank=%d clamp=%d ipi_ret=%d\n",
		bank_id, volt_clamp, ret);
	return count;
}

/* ---- /proc/eem/offset (RW): "<bank_id> <offset>" ---- */
static int eem_offset_show(struct seq_file *m, void *v)
{
	seq_puts(m, "write: \"<bank_id 0..3> <offset>\"\n");
	return 0;
}

static ssize_t eem_offset_write(struct file *f, const char __user *ubuf,
				size_t count, loff_t *pos)
{
	char buf[64], *p, *tok;
	struct eemsn_ipi_data eem_data;
	int bank_id = 0, offset = 0, ret;

	if (count == 0 || count >= sizeof(buf))
		return -EINVAL;
	if (copy_from_user(buf, ubuf, count))
		return -EFAULT;
	buf[count] = '\0';
	p = buf;

	tok = strsep(&p, " ");
	if (!tok || kstrtoint(tok, 10, &bank_id))
		return -EINVAL;
	if (bank_id < 0 || bank_id >= NR_EEMSN_DET)
		return -EINVAL;
	if (!p || kstrtoint(strim(p), 10, &offset))
		return -EINVAL;

	memset(&eem_data, 0, sizeof(eem_data));
	eem_data.u.data.arg[0] = bank_id;
	eem_data.u.data.arg[1] = offset;
	ret = eem_to_up(IPI_EEMSN_OFFSET_PROC_WRITE, &eem_data);
	pr_info("rodin_eem: offset bank=%d offset=%d ipi_ret=%d\n",
		bank_id, offset, ret);
	return count;
}

/* ---- /proc/eem/cur_volt (RO): triggers GET_EEM_VOLT + dumps the DVFS table ---- */
static int eem_cur_volt_show(struct seq_file *m, void *v)
{
	struct eemsn_ipi_data eem_data;
	struct eemsn_log *log;
	int ipi_ret, i, bank_id, locklimit = 0;
	unsigned char lock;

	memset(&eem_data, 0, sizeof(eem_data));
	ipi_ret = eem_to_up(IPI_EEMSN_GET_EEM_VOLT, &eem_data);
	seq_printf(m, "ipi_ret:%d\n", ipi_ret);

	log = eem_get_log();
	if (!log) {
		seq_puts(m, "eemsn_log unavailable (mtk_get_eemsn_log unresolved)\n");
		return 0;
	}

	while (1) {
		lock = log->lock;
		locklimit++;
		mdelay(5);
		lock = log->lock;
		if ((lock & 0x1) && (locklimit < 5))
			continue;
		break;
	}

	for (bank_id = 0; bank_id < NR_EEMSN_DET; bank_id++) {
		seq_printf(m, "id:%d, clamp=%d offset=%d, DVFS_TABLE\n", bank_id,
			   log->det_log[bank_id].volt_clamp,
			   log->det_log[bank_id].volt_offset);
		for (i = 0; i < NR_FREQ; i++) {
			if (log->det_log[bank_id].freq_tbl[i] == 0)
				break;
			seq_printf(m, "[%d] freq=%hu eem=%x pmic=%x\n", i,
				   log->det_log[bank_id].freq_tbl[i],
				   log->det_log[bank_id].volt_tbl_init2[i],
				   log->det_log[bank_id].volt_tbl_pmic[i]);
		}
	}
	return 0;
}

/* ---- /proc/eem/debug (RW): "<bank_id> <disable>" — enable/disable per-bank ---- */
static int eem_debug_show(struct seq_file *m, void *v)
{
	return 0;
}

static ssize_t eem_debug_write(struct file *f, const char __user *ubuf,
			       size_t count, loff_t *pos)
{
	char buf[64], *p, *tok;
	struct eemsn_ipi_data eem_data;
	int bank_id = 0, disable = 0;

	if (count == 0 || count >= sizeof(buf))
		return -EINVAL;
	if (copy_from_user(buf, ubuf, count))
		return -EFAULT;
	buf[count] = '\0';
	p = buf;

	tok = strsep(&p, " ");
	if (!tok || kstrtoint(tok, 10, &bank_id))
		return -EINVAL;
	if (bank_id < 0 || bank_id >= NR_EEMSN_DET)
		return -EINVAL;
	if (!p || kstrtoint(strim(p), 10, &disable))
		return -EINVAL;

	memset(&eem_data, 0, sizeof(eem_data));
	eem_data.u.data.arg[0] = bank_id;
	eem_data.u.data.arg[1] = disable;
	eem_to_up(IPI_EEMSN_DEBUG_PROC_WRITE, &eem_data);
	return count;
}

/* ---- /proc/eem/disable (RW): global EEMSN enable/disable ---- */
static int eem_disable_show(struct seq_file *m, void *v)
{
	struct eemsn_log *log = eem_get_log();

	if (log)
		seq_printf(m, "eemsn_disable:%d\n", log->eemsn_disable);
	else
		seq_puts(m, "eemsn_log unavailable\n");
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

	eemsn_log = eem_get_log();	/* best-effort */

	/* register the AP side of CH_S_EEMSN (eem-dbg normally does this) */
	if (get_mcupm_ipidev && mtk_ipi_register) {
		ipidev = get_mcupm_ipidev();
		if (ipidev) {
			err = mtk_ipi_register(ipidev, CH_S_EEMSN, NULL, NULL,
					       &ipi_ackdata);
			if (err)
				pr_info("rodin_eem: ipi_register ret=%d (maybe already registered)\n",
					err);
			else
				ipi_registered = true;
		}
	} else {
		pr_warn("rodin_eem: mcupm/ipi symbols unresolved at init\n");
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

	pr_info("rodin_eem: /proc/eem ready (ipi_reg=%d, log=%p, sym=%d)\n",
		ipi_registered, eemsn_log, (get_mcupm_ipidev && mtk_ipi_send_compl) ? 1 : 0);
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
