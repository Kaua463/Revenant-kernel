// SPDX-License-Identifier: GPL-2.0
/*
 * rodin_gpueb.c — controlled IPI probe for the GPUEB coprocessor (mt6899/rodin).
 *
 * Purpose: send a fully-controllable 8-word (32-byte) IPI message to a named
 * GPUEB channel, to dynamically test a static-analysis candidate bug in the
 * GPUEB firmware's debug command dispatcher (gpueb_debug_cmd_dispatch_chain,
 * ram:0x9b6e in gpueb_code.bin): cmd_id==0x11 reaches a table-index write with
 * no bounds check (gpueb_fixcmd_write_bound_then_STRICT_check, ram:0x9e24).
 * cmd_id==0x10 is a known-safe sibling handler (bounds-checked), used as a
 * canary to confirm the channel/dispatch path is actually reached before
 * trying 0x11.
 *
 * Message layout (reverse-engineered from the GPUEB firmware ISR at ram:0x9ae0,
 * which reads an 8-word buffer): word0=magic(0x02812969, checked by firmware),
 * word1=cmd_id, word2..word7=args (word4/word5 feed cmd_id==0x11's sub-handler).
 *
 * Mechanism: same as the vendor's own /proc/gpueb_hw_voter/hw_voter_dbg debug
 * node (mtk_gpueb.ko, gpueb_hw_voter_dbg_proc_write) — resolve a channel name
 * to a pin_id via gpueb_get_send_PIN_ID_by_name(), then send via
 * mtk_ipi_send_compl_to_gpueb(). Confirmed working on-device (IPI_ID_CCF probe,
 * clean timeout, no crash) before writing this module.
 *
 * Vendor symbols are STRONG externs, called directly (never address-taken):
 * a weak fn whose address is taken forces a GOT relocation
 * (R_AARCH64_LD64_GOT_LO12_NC=312) which the arm64 module loader rejects.
 * Direct calls emit CALL26, resolved via module PLTs at insmod. Confirmed
 * exported by mtk_gpueb.ko: gpueb_get_send_PIN_ID_by_name, mtk_ipi_send_compl_to_gpueb.
 *
 * Safety: writes are staged by the caller (userspace), not by this module —
 * this module has no built-in escalation. /proc/rodin_gpueb/resolve only
 * resolves a channel name (no send). /proc/rodin_gpueb/send performs exactly
 * one send per write, no retry/loop, and logs pin_id + ipi ret via pr_info so
 * results are visible in dmesg.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include <linux/string.h>

#define GPUEB_IPI_MAGIC		0x02812969u
#define GPUEB_IPI_TIMEOUT_MS	500

/* vendor symbols, resolved at insmod from mtk_gpueb.ko */
extern int gpueb_get_send_PIN_ID_by_name(const char *name) __attribute__((weak));
extern int mtk_ipi_send_compl_to_gpueb(int pin_id, int flag, void *data,
					int size, int timeout_ms) __attribute__((weak));

struct gpueb_msg {
	unsigned int word[8];
};

/* ---- /proc/rodin_gpueb/resolve (RW): write a channel name, read back pin_id ---- */
static int g_last_resolved_pin = -2; /* -2 = never resolved */
static char g_last_resolved_name[32];

static int resolve_show(struct seq_file *m, void *v)
{
	seq_printf(m, "write a channel name (e.g. IPI_ID_GPUFREQ) to resolve its pin_id\n");
	seq_printf(m, "last: name=\"%s\" pin_id=%d\n", g_last_resolved_name, g_last_resolved_pin);
	return 0;
}

static ssize_t resolve_write(struct file *f, const char __user *ubuf,
			      size_t count, loff_t *pos)
{
	char buf[32];
	int pin;

	if (count == 0 || count >= sizeof(buf))
		return -EINVAL;
	if (copy_from_user(buf, ubuf, count))
		return -EFAULT;
	buf[count] = '\0';
	strim(buf);

	pin = gpueb_get_send_PIN_ID_by_name(buf);
	strscpy(g_last_resolved_name, buf, sizeof(g_last_resolved_name));
	g_last_resolved_pin = pin;
	pr_info("rodin_gpueb: resolve(\"%s\") -> pin_id=%d\n", buf, pin);
	return count;
}

/* ---- /proc/rodin_gpueb/send (RW): "<channel_name> <cmd_id> <w2> <w3> <w4> <w5> <w6> <w7>" (hex) ---- */
static int g_last_ret = -2;
static struct gpueb_msg g_last_msg;
static int g_last_pin = -2;

static int send_show(struct seq_file *m, void *v)
{
	int i;

	seq_puts(m, "write: \"<channel_name> <cmd_id_hex> <w2> <w3> <w4> <w5> <w6> <w7>\" (all hex, no 0x prefix needed)\n");
	seq_printf(m, "last: pin_id=%d ipi_ret=%d msg=[", g_last_pin, g_last_ret);
	for (i = 0; i < 8; i++)
		seq_printf(m, "%08x%s", g_last_msg.word[i], i == 7 ? "" : " ");
	seq_puts(m, "]\n");
	return 0;
}

static ssize_t send_write(struct file *f, const char __user *ubuf,
			   size_t count, loff_t *pos)
{
	char buf[160];
	char *p, *tok;
	char name[32];
	unsigned int vals[7]; /* cmd_id, w2..w7 */
	int i, pin, ret;
	struct gpueb_msg msg;

	if (count == 0 || count >= sizeof(buf))
		return -EINVAL;
	if (copy_from_user(buf, ubuf, count))
		return -EFAULT;
	buf[count] = '\0';
	p = buf;

	tok = strsep(&p, " \t\n");
	if (!tok || !*tok)
		return -EINVAL;
	strscpy(name, tok, sizeof(name));

	for (i = 0; i < 7; i++) {
		tok = strsep(&p, " \t\n");
		if (!tok || !*tok || kstrtouint(tok, 16, &vals[i]))
			return -EINVAL;
	}

	pin = gpueb_get_send_PIN_ID_by_name(name);
	if (pin < 0) {
		pr_warn("rodin_gpueb: send: channel \"%s\" did not resolve (pin=%d), aborting\n",
			name, pin);
		g_last_pin = pin;
		g_last_ret = -ENODEV;
		return count;
	}

	msg.word[0] = GPUEB_IPI_MAGIC;
	for (i = 0; i < 7; i++)
		msg.word[1 + i] = vals[i];

	ret = mtk_ipi_send_compl_to_gpueb(pin, 0, &msg, sizeof(msg), GPUEB_IPI_TIMEOUT_MS);

	g_last_pin = pin;
	g_last_ret = ret;
	g_last_msg = msg;

	pr_info("rodin_gpueb: send channel=\"%s\" pin_id=%d cmd_id=0x%x w2..w7=[%x %x %x %x %x %x] ipi_ret=%d\n",
		name, pin, vals[0], vals[1], vals[2], vals[3], vals[4], vals[5], ret);

	return count;
}

#define GPUEB_RW(nm)							\
static int nm##_open(struct inode *i, struct file *f)			\
{ return single_open(f, nm##_show, NULL); }				\
static const struct proc_ops nm##_ops = {				\
	.proc_open = nm##_open, .proc_read = seq_read,			\
	.proc_lseek = seq_lseek, .proc_release = single_release,	\
	.proc_write = nm##_write,					\
}

GPUEB_RW(resolve);
GPUEB_RW(send);

static struct proc_dir_entry *gpueb_probe_dir;

static int __init rodin_gpueb_init(void)
{
	gpueb_probe_dir = proc_mkdir("rodin_gpueb", NULL);
	if (!gpueb_probe_dir) {
		pr_err("rodin_gpueb: failed to create /proc/rodin_gpueb\n");
		return -ENOMEM;
	}
	proc_create("resolve", 0664, gpueb_probe_dir, &resolve_ops);
	proc_create("send",    0664, gpueb_probe_dir, &send_ops);

	pr_info("rodin_gpueb: /proc/rodin_gpueb ready\n");
	return 0;
}

static void __exit rodin_gpueb_exit(void)
{
	proc_remove(gpueb_probe_dir);
}

module_init(rodin_gpueb_init);
module_exit(rodin_gpueb_exit);

MODULE_DESCRIPTION("Revenant GPUEB IPI probe — controlled msg send for dynamic bug confirmation");
MODULE_AUTHOR("Kaua / Revenant");
MODULE_LICENSE("GPL v2");
