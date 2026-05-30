// SPDX-License-Identifier: GPL-2.0-only
/*
 * Revenant /proc/rodin — kernel-owned control interface (v1.5)
 *
 * Architecture (SCOPE secao E/I6): a maioria dos levers de hardware (cpu_limits,
 * scaling_max, devfreq, uclamp, cpuset, io-sched) esta BLOQUEADA pro dominio
 * SELinux do app (u:r:ksu:s0) neste kernel/SuSFS. A solucao limpa e o app
 * escrever AQUI (no kernel-owned proc), e o KERNEL aplicar os levers
 * INTERNAMENTE (codigo kernel nao e confinado por SELinux).
 *
 * v0 (este arquivo) = SO A INTERFACE + estado. DEFENSIVO:
 *   - NAO muta o sistema no boot (default mode=none / thermal_profile=stock = no-op)
 *   - NAO instala hook em hot path
 *   - => nao pode bootloopar
 * Os "apply hooks" (freezer/uclamp/cpuset/swappiness) sao STUBS marcados TODO;
 * so entram depois de validar no device a writability SELinux deste no (ver
 * SCOPE I6/J5) e a estabilidade de cada lever.
 *
 * NOTA thermal_profile: a curva ROG mora no driver termico VENDOR (mtk), que NAO
 * existe no GKI build. Aqui thermal_profile so ARMAZENA a escolha; quem aplica a
 * curva e o modulo KSU config-edit (SCOPE J3), que pode ler este no.
 */

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include <linux/mutex.h>
#include <linux/string.h>
#include <linux/uidgid.h>

#define RODIN_VERSION_STR	"Revenant v1.5 (rodin)"

#define RODIN_MODE_NONE		0
#define RODIN_MODE_GAME		1
#define RODIN_MODE_GAME_CALL	2
#define RODIN_MODE_MULTITASK	3
#define RODIN_MODE_IOSLIKE	4

#define RODIN_THERM_STOCK	0
#define RODIN_THERM_BALANCED	1
#define RODIN_THERM_ROG		2

#define RODIN_WL_MAX		64	/* max user whitelist entries */
#define RODIN_PKG_MAX		128	/* max pkgname length */

/* AID_SYSTEM — deixa o grupo "system" escrever (DAC). SELinux e separado. */
#define RODIN_GID_SYSTEM	1000

static DEFINE_MUTEX(rodin_lock);

static int rodin_mode = RODIN_MODE_NONE;
static int rodin_therm = RODIN_THERM_STOCK;
static pid_t rodin_fg_pid;

static char rodin_whitelist[RODIN_WL_MAX][RODIN_PKG_MAX];
static int rodin_wl_count;

/* Sistema critico — NUNCA congelar/matar (SCOPE MODES_SPEC). Read-only. */
static const char * const rodin_protected[] = {
	"com.android.systemui",
	"com.android.phone",
	"com.android.server.telecom",
	"com.android.bluetooth",
	"com.android.nfc",
	"com.android.se",
	"com.miui.securitycenter",
	"com.miui.home",
	"com.google.android.gms",
};

static const char *rodin_mode_name(int m)
{
	switch (m) {
	case RODIN_MODE_GAME:		return "game";
	case RODIN_MODE_GAME_CALL:	return "game_call";
	case RODIN_MODE_MULTITASK:	return "multitask";
	case RODIN_MODE_IOSLIKE:	return "ioslike";
	default:			return "none";
	}
}

static const char *rodin_therm_name(int t)
{
	switch (t) {
	case RODIN_THERM_ROG:		return "rog";
	case RODIN_THERM_BALANCED:	return "balanced";
	default:			return "stock";
	}
}

/*
 * rodin_apply_mode — aplica os levers do modo IN-KERNEL.
 *
 * STUB v0: intencionalmente vazio. Aqui entram (increment 3, apos validacao
 * no device) os levers que o app nao consegue por SELinux:
 *   - cgroup freezer dos uids background (exceto whitelist + protected)
 *   - uclamp.min do top-app / uclamp.max do bg
 *   - cpuset top-app full cores vs restrito
 *   - vm.swappiness por modo
 * Cada um entra individualmente, validado, reversivel. NADA roda no boot.
 */
static void rodin_apply_mode(int mode)
{
	/* TODO(increment 3): aplicar levers validados. v0 = no-op (boot-safe). */
}

/* ---- mode ---- */
static int rodin_mode_show(struct seq_file *m, void *v)
{
	mutex_lock(&rodin_lock);
	seq_printf(m, "%s\n", rodin_mode_name(rodin_mode));
	mutex_unlock(&rodin_lock);
	return 0;
}

static int rodin_mode_open(struct inode *i, struct file *f)
{
	return single_open(f, rodin_mode_show, NULL);
}

static ssize_t rodin_mode_write(struct file *f, const char __user *buf,
				size_t len, loff_t *off)
{
	char kbuf[16];
	int newmode;

	if (len == 0 || len >= sizeof(kbuf))
		return -EINVAL;
	if (copy_from_user(kbuf, buf, len))
		return -EFAULT;
	kbuf[len] = '\0';
	strim(kbuf);

	if (!strcmp(kbuf, "game"))		newmode = RODIN_MODE_GAME;
	else if (!strcmp(kbuf, "game_call"))	newmode = RODIN_MODE_GAME_CALL;
	else if (!strcmp(kbuf, "multitask"))	newmode = RODIN_MODE_MULTITASK;
	else if (!strcmp(kbuf, "ioslike"))	newmode = RODIN_MODE_IOSLIKE;
	else if (!strcmp(kbuf, "none"))		newmode = RODIN_MODE_NONE;
	else					return -EINVAL;

	mutex_lock(&rodin_lock);
	rodin_mode = newmode;
	rodin_apply_mode(newmode);
	mutex_unlock(&rodin_lock);
	return len;
}

static const struct proc_ops rodin_mode_ops = {
	.proc_open	= rodin_mode_open,
	.proc_read	= seq_read,
	.proc_lseek	= seq_lseek,
	.proc_release	= single_release,
	.proc_write	= rodin_mode_write,
};

/* ---- thermal_profile ---- */
static int rodin_therm_show(struct seq_file *m, void *v)
{
	mutex_lock(&rodin_lock);
	seq_printf(m, "%s\n", rodin_therm_name(rodin_therm));
	mutex_unlock(&rodin_lock);
	return 0;
}

static int rodin_therm_open(struct inode *i, struct file *f)
{
	return single_open(f, rodin_therm_show, NULL);
}

static ssize_t rodin_therm_write(struct file *f, const char __user *buf,
				 size_t len, loff_t *off)
{
	char kbuf[16];
	int newt;

	if (len == 0 || len >= sizeof(kbuf))
		return -EINVAL;
	if (copy_from_user(kbuf, buf, len))
		return -EFAULT;
	kbuf[len] = '\0';
	strim(kbuf);

	if (!strcmp(kbuf, "rog"))		newt = RODIN_THERM_ROG;
	else if (!strcmp(kbuf, "balanced"))	newt = RODIN_THERM_BALANCED;
	else if (!strcmp(kbuf, "stock"))	newt = RODIN_THERM_STOCK;
	else					return -EINVAL;

	mutex_lock(&rodin_lock);
	rodin_therm = newt;	/* so armazena; curva aplica via modulo KSU (SCOPE J3) */
	mutex_unlock(&rodin_lock);
	return len;
}

static const struct proc_ops rodin_therm_ops = {
	.proc_open	= rodin_therm_open,
	.proc_read	= seq_read,
	.proc_lseek	= seq_lseek,
	.proc_release	= single_release,
	.proc_write	= rodin_therm_write,
};

/* ---- whitelist (rw) ---- */
static int rodin_wl_show(struct seq_file *m, void *v)
{
	int i;

	mutex_lock(&rodin_lock);
	for (i = 0; i < rodin_wl_count; i++)
		seq_printf(m, "%s\n", rodin_whitelist[i]);
	mutex_unlock(&rodin_lock);
	return 0;
}

static int rodin_wl_open(struct inode *i, struct file *f)
{
	return single_open(f, rodin_wl_show, NULL);
}

/*
 * write protocol:
 *   "clear"      -> esvazia a lista
 *   "<pkgname>"  -> adiciona (ignora duplicata; -ENOSPC se cheia)
 */
static ssize_t rodin_wl_write(struct file *f, const char __user *buf,
			      size_t len, loff_t *off)
{
	char kbuf[RODIN_PKG_MAX];
	int i;

	if (len == 0 || len >= sizeof(kbuf))
		return -EINVAL;
	if (copy_from_user(kbuf, buf, len))
		return -EFAULT;
	kbuf[len] = '\0';
	strim(kbuf);
	if (kbuf[0] == '\0')
		return -EINVAL;

	mutex_lock(&rodin_lock);
	if (!strcmp(kbuf, "clear")) {
		rodin_wl_count = 0;
		mutex_unlock(&rodin_lock);
		return len;
	}
	for (i = 0; i < rodin_wl_count; i++) {
		if (!strcmp(rodin_whitelist[i], kbuf)) {
			mutex_unlock(&rodin_lock);
			return len;	/* ja existe */
		}
	}
	if (rodin_wl_count >= RODIN_WL_MAX) {
		mutex_unlock(&rodin_lock);
		return -ENOSPC;
	}
	strscpy(rodin_whitelist[rodin_wl_count], kbuf, RODIN_PKG_MAX);
	rodin_wl_count++;
	mutex_unlock(&rodin_lock);
	return len;
}

static const struct proc_ops rodin_wl_ops = {
	.proc_open	= rodin_wl_open,
	.proc_read	= seq_read,
	.proc_lseek	= seq_lseek,
	.proc_release	= single_release,
	.proc_write	= rodin_wl_write,
};

/* ---- protected_sys (r) ---- */
static int rodin_prot_show(struct seq_file *m, void *v)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(rodin_protected); i++)
		seq_printf(m, "%s\n", rodin_protected[i]);
	return 0;
}

static int rodin_prot_open(struct inode *i, struct file *f)
{
	return single_open(f, rodin_prot_show, NULL);
}

static const struct proc_ops rodin_prot_ops = {
	.proc_open	= rodin_prot_open,
	.proc_read	= seq_read,
	.proc_lseek	= seq_lseek,
	.proc_release	= single_release,
};

/* ---- foreground_pid (rw) ---- */
static int rodin_fg_show(struct seq_file *m, void *v)
{
	mutex_lock(&rodin_lock);
	seq_printf(m, "%d\n", rodin_fg_pid);
	mutex_unlock(&rodin_lock);
	return 0;
}

static int rodin_fg_open(struct inode *i, struct file *f)
{
	return single_open(f, rodin_fg_show, NULL);
}

static ssize_t rodin_fg_write(struct file *f, const char __user *buf,
			      size_t len, loff_t *off)
{
	char kbuf[16];
	int pid;

	if (len == 0 || len >= sizeof(kbuf))
		return -EINVAL;
	if (copy_from_user(kbuf, buf, len))
		return -EFAULT;
	kbuf[len] = '\0';
	strim(kbuf);
	if (kstrtoint(kbuf, 10, &pid) || pid < 0)
		return -EINVAL;

	mutex_lock(&rodin_lock);
	rodin_fg_pid = pid;
	mutex_unlock(&rodin_lock);
	return len;
}

static const struct proc_ops rodin_fg_ops = {
	.proc_open	= rodin_fg_open,
	.proc_read	= seq_read,
	.proc_lseek	= seq_lseek,
	.proc_release	= single_release,
	.proc_write	= rodin_fg_write,
};

/* ---- version (r) ---- */
static int rodin_ver_show(struct seq_file *m, void *v)
{
	seq_printf(m, "%s\n", RODIN_VERSION_STR);
	return 0;
}

static int rodin_ver_open(struct inode *i, struct file *f)
{
	return single_open(f, rodin_ver_show, NULL);
}

static const struct proc_ops rodin_ver_ops = {
	.proc_open	= rodin_ver_open,
	.proc_read	= seq_read,
	.proc_lseek	= seq_lseek,
	.proc_release	= single_release,
};

/* ---- stats (r) ---- */
static int rodin_stats_show(struct seq_file *m, void *v)
{
	mutex_lock(&rodin_lock);
	seq_printf(m, "mode=%s\n", rodin_mode_name(rodin_mode));
	seq_printf(m, "thermal_profile=%s\n", rodin_therm_name(rodin_therm));
	seq_printf(m, "foreground_pid=%d\n", rodin_fg_pid);
	seq_printf(m, "whitelist_count=%d\n", rodin_wl_count);
	mutex_unlock(&rodin_lock);
	return 0;
}

static int rodin_stats_open(struct inode *i, struct file *f)
{
	return single_open(f, rodin_stats_show, NULL);
}

static const struct proc_ops rodin_stats_ops = {
	.proc_open	= rodin_stats_open,
	.proc_read	= seq_read,
	.proc_lseek	= seq_lseek,
	.proc_release	= single_release,
};

static struct proc_dir_entry *rodin_dir;

/* cria no rw com dono root:system (DAC). SELinux label tratado em policy. */
static void rodin_create(const char *name, umode_t mode,
			 const struct proc_ops *ops)
{
	struct proc_dir_entry *e = proc_create(name, mode, rodin_dir, ops);

	if (e)
		proc_set_user(e, GLOBAL_ROOT_UID, KGIDT_INIT(RODIN_GID_SYSTEM));
}

static int __init rodin_init(void)
{
	rodin_dir = proc_mkdir("rodin", NULL);
	if (!rodin_dir) {
		pr_err("rodin: failed to create /proc/rodin\n");
		return -ENOMEM;
	}

	rodin_create("mode",            0664, &rodin_mode_ops);
	rodin_create("thermal_profile", 0664, &rodin_therm_ops);
	rodin_create("whitelist",       0664, &rodin_wl_ops);
	rodin_create("foreground_pid",  0664, &rodin_fg_ops);
	rodin_create("protected_sys",   0444, &rodin_prot_ops);
	rodin_create("stats",           0444, &rodin_stats_ops);
	rodin_create("version",         0444, &rodin_ver_ops);

	pr_info("rodin: /proc/rodin ready (%s)\n", RODIN_VERSION_STR);
	return 0;
}

static void __exit rodin_exit(void)
{
	proc_remove(rodin_dir);
}

module_init(rodin_init);
module_exit(rodin_exit);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Kaua / Revenant");
MODULE_DESCRIPTION("Revenant /proc/rodin game-mode control interface");
