// SPDX-License-Identifier: GPL-2.0
//
// rodin_shared_hack — direct write to GPUEB shared status memory
//
// Premise (from Mayuri-Chan MTK source):
//   AP and GPUEB share a reserved memory region at phys addr 0x7F880000 (rodin
//   DTS gpueb_mem_addr). The struct gpufreq_shared_status lives at offset 0.
//   AP mounts via ioremap_wc — full RW access. GPUEB caches its values but
//   also reads from shared memory for proc display data.
//
// Bypass idea: writing test_mode = TEST_PRIVILEGE (2) directly bypasses the
// IPI gate (CMD_SET_MFGSYS_CONFIG with target=CONFIG_TEST_MODE is dropped by
// GPUEB in retail firmware). After our direct write:
//   - /proc/gpufreqv2/gpufreq_status shows "TestMode: Privilege" (AP reads
//     from shared via g_shared_status)
//   - whitebox_test_proc_write AP-side gate passes (it checks shared)
//   - if GPUEB also reads from shared for fix_custom_freq_volt validation,
//     undervolt unlocked
//
// Struct field offsets (counted from Mayuri-Chan v2/include/gpufreq_v2.h):
//   magic                : 0x000 (int)
//   cur_oppidx_gpu       : 0x004
//   ... 16 more ints ...
//   ... 35 unsigned ints up to 0x120 ...
//   stress_test          : 0x124 (offset 292)
//   test_mode            : 0x128 (offset 296) ← TARGET
//   ips_mode             : 0x12C
//   ... etc
//
// All proven safe paths: read-only by default. Use proc nodes to commit writes.

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/io.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include <linux/string.h>

/* From rodin DTS: /proc/device-tree/soc/gpueb@13c00000/gpueb_mem_addr */
#define GPUEB_SHARED_PA          0x7F880000UL
#define GPUFREQ_SHARED_SIZE      0x4000           /* first sub-region = gpufreq */

/* MFG_HBVC region (gpufreq_reg_mt6899.h) — GPU Hardware Bus Voltage Control.
 * AP source devm_ioremaps this for debug-only reads (FLL/GRP frontend/backend).
 * GPUEB has __gpufreq_hbvc_set_vlower_gpu/_stack which writes elsewhere in
 * this same region. Risk: DEVAPC protected on some offsets — we read SAFE
 * known-AP offsets first (0x400/0x404/0x480/0x484), then sweep cautiously.
 */
#define HBVC_PA                  0x13F50000UL
#define HBVC_SIZE                0x1000
#define HBVC_OFF_FLL0_FRONTEND   0x400  /* AP confirmed reads */
#define HBVC_OFF_FLL1_FRONTEND   0x404
#define HBVC_OFF_GRP0_BACKEND    0x480
#define HBVC_OFF_GRP1_BACKEND    0x484

/* MTK cpufreq-hw CSRAM (mediatek-cpufreq-hw_main.c, mt6899 DTS):
 * 3 clusters performance-domain0/1/2 at 0x0c0dd360 / 0x480 / 0x5a0, 0x120 bytes each.
 * LUT_FREQ = data & 0xFFF, freq_khz = freq_field * 1000. LUT_ROW_SIZE = 4. MAX = 32.
 */
#define CPULUT_PA                0x0c0dd000UL
#define CPULUT_SIZE              0x1000           /* page-aligned, covers all 3 clusters */
#define CPULUT_OFF_PD0           0x360            /* eff cluster (cpu0-3) */
#define CPULUT_OFF_PD1           0x480            /* perf cluster (cpu4-6) */
#define CPULUT_OFF_PD2           0x5A0            /* prime cluster (cpu7) */
#define CPULUT_PER_DOMAIN        0x120            /* per-domain register block */
#define CPULUT_MAX_ENTRIES       32
#define CPULUT_FREQ_MASK         0xFFF            /* GENMASK(11, 0) */

/* Offsets in struct gpufreq_shared_status (Mayuri-Chan MT6899 source) */
#define OFF_MAGIC                0x000
#define OFF_CUR_OPPIDX_GPU       0x004
#define OFF_CUR_OPPIDX_STACK     0x008
#define OFF_STRESS_TEST          0x124
#define OFF_TEST_MODE            0x128
#define OFF_IPS_MODE             0x12C
#define OFF_AGING_MARGIN         0x0E4
#define OFF_AVS_MARGIN           0x0EC

/* enum gpufreq_test_mode */
#define TEST_NORMAL              0
#define TEST_ADVANCED            1
#define TEST_PRIVILEGE           2

static void __iomem *shared_va;
static void __iomem *cpulut_va;
static void __iomem *hbvc_va;
static u32 last_set_test_mode;

static int snap_show(struct seq_file *m, void *v)
{
	if (!shared_va) {
		seq_puts(m, "shared_va = NULL (ioremap failed)\n");
		return 0;
	}

	seq_printf(m,
		"phys_base: 0x%lx, size: 0x%x\n"
		"--- shared_status snapshot ---\n"
		"magic           @0x000 = 0x%08x\n"
		"cur_oppidx_gpu  @0x004 = %d\n"
		"cur_oppidx_stk  @0x008 = %d\n"
		"stress_test     @0x124 = %u\n"
		"test_mode       @0x128 = %u  (0=NORMAL 1=ADVANCED 2=PRIVILEGE)\n"
		"ips_mode        @0x12C = %u\n"
		"aging_margin    @0x0E4 = %u\n"
		"avs_margin      @0x0EC = %u\n"
		"--- our last write ---\n"
		"last_set_test_mode = %u\n",
		GPUEB_SHARED_PA, GPUFREQ_SHARED_SIZE,
		readl(shared_va + OFF_MAGIC),
		(int)readl(shared_va + OFF_CUR_OPPIDX_GPU),
		(int)readl(shared_va + OFF_CUR_OPPIDX_STACK),
		readl(shared_va + OFF_STRESS_TEST),
		readl(shared_va + OFF_TEST_MODE),
		readl(shared_va + OFF_IPS_MODE),
		readl(shared_va + OFF_AGING_MARGIN),
		readl(shared_va + OFF_AVS_MARGIN),
		last_set_test_mode);
	return 0;
}

static int snap_open(struct inode *i, struct file *f)
{
	return single_open(f, snap_show, NULL);
}

/* /proc/rodin_shared_hack/test_mode — write integer 0/1/2 to force test_mode */
static ssize_t test_mode_write(struct file *f, const char __user *ub,
			       size_t n, loff_t *o)
{
	char buf[16];
	u32 val;

	if (!shared_va)
		return -ENODEV;
	if (!n || n >= sizeof(buf))
		return -EINVAL;
	if (copy_from_user(buf, ub, n))
		return -EFAULT;
	buf[n] = '\0';
	if (kstrtouint(strim(buf), 0, &val))
		return -EINVAL;
	if (val > 2)
		return -EINVAL;

	writel(val, shared_va + OFF_TEST_MODE);
	/* memory barrier ensures the write reaches RAM before any subsequent read by GPUEB */
	wmb();
	last_set_test_mode = val;

	pr_info("rodin_shared_hack: wrote test_mode=%u at phys=0x%lx+0x%x\n",
		val, GPUEB_SHARED_PA, OFF_TEST_MODE);
	return n;
}

static int test_mode_show(struct seq_file *m, void *v)
{
	if (!shared_va) {
		seq_puts(m, "ENODEV\n");
		return 0;
	}
	seq_printf(m, "%u\n", readl(shared_va + OFF_TEST_MODE));
	return 0;
}

static int test_mode_open(struct inode *i, struct file *f)
{
	return single_open(f, test_mode_show, NULL);
}

/* /proc/rodin_shared_hack/raw_write — "offset value" generic poke (debug) */
static ssize_t raw_write(struct file *f, const char __user *ub,
			 size_t n, loff_t *o)
{
	char buf[64];
	u32 off = 0, val = 0;

	if (!shared_va)
		return -ENODEV;
	if (!n || n >= sizeof(buf))
		return -EINVAL;
	if (copy_from_user(buf, ub, n))
		return -EFAULT;
	buf[n] = '\0';
	if (sscanf(buf, "%x %x", &off, &val) != 2)
		return -EINVAL;
	if (off >= GPUFREQ_SHARED_SIZE - 3 || (off & 3))
		return -EINVAL;

	writel(val, shared_va + off);
	wmb();
	pr_info("rodin_shared_hack: raw write phys=0x%lx+0x%x = 0x%x\n",
		GPUEB_SHARED_PA, off, val);
	return n;
}

static int raw_show(struct seq_file *m, void *v)
{
	seq_puts(m, "write: \"<hex_off> <hex_val>\" (4-byte aligned, off < 0x4000)\n");
	return 0;
}

static int raw_open(struct inode *i, struct file *f)
{
	return single_open(f, raw_show, NULL);
}

static const struct proc_ops snap_ops = {
	.proc_open = snap_open, .proc_read = seq_read,
	.proc_lseek = seq_lseek, .proc_release = single_release,
};

static const struct proc_ops test_mode_ops = {
	.proc_open = test_mode_open, .proc_read = seq_read,
	.proc_lseek = seq_lseek, .proc_release = single_release,
	.proc_write = test_mode_write,
};

static const struct proc_ops raw_ops = {
	.proc_open = raw_open, .proc_read = seq_read,
	.proc_lseek = seq_lseek, .proc_release = single_release,
	.proc_write = raw_write,
};

/* /proc/rodin_shared_hack/find — read returns offsets where given u32 lives.
 * Usage: write "0x13D620" (= 1300000 freq) -> read shows hex offsets. */
static u32 g_find_value;

static int find_show(struct seq_file *m, void *v)
{
	int i, n = 0;
	if (!shared_va) {
		seq_puts(m, "ENODEV\n");
		return 0;
	}
	seq_printf(m, "searching for 0x%08x in 0x%x bytes...\n",
		g_find_value, GPUFREQ_SHARED_SIZE);
	for (i = 0; i < GPUFREQ_SHARED_SIZE - 3; i += 4) {
		if (readl(shared_va + i) == g_find_value) {
			seq_printf(m, "  hit @ 0x%04x\n", i);
			n++;
			if (n >= 20) {
				seq_puts(m, "  ... (cap 20)\n");
				break;
			}
		}
	}
	seq_printf(m, "total: %d\n", n);
	return 0;
}

static ssize_t find_write(struct file *f, const char __user *ub,
			  size_t n, loff_t *o)
{
	char buf[32];
	if (!n || n >= sizeof(buf))
		return -EINVAL;
	if (copy_from_user(buf, ub, n))
		return -EFAULT;
	buf[n] = '\0';
	if (kstrtouint(strim(buf), 0, &g_find_value))
		return -EINVAL;
	return n;
}

static int find_open(struct inode *i, struct file *f)
{
	return single_open(f, find_show, NULL);
}

static const struct proc_ops find_ops = {
	.proc_open = find_open, .proc_read = seq_read,
	.proc_lseek = seq_lseek, .proc_release = single_release,
	.proc_write = find_write,
};

/* /proc/rodin_shared_hack/peek — show 4-byte aligned u32 at offset given via write */
static u32 g_peek_offset;

static int peek_show(struct seq_file *m, void *v)
{
	if (!shared_va || g_peek_offset >= GPUFREQ_SHARED_SIZE - 3) {
		seq_printf(m, "off=0x%x: invalid\n", g_peek_offset);
		return 0;
	}
	seq_printf(m, "off=0x%04x: 0x%08x  (u32 le)\n",
		g_peek_offset, readl(shared_va + g_peek_offset));
	return 0;
}

static ssize_t peek_write(struct file *f, const char __user *ub,
			  size_t n, loff_t *o)
{
	char buf[32];
	if (!n || n >= sizeof(buf))
		return -EINVAL;
	if (copy_from_user(buf, ub, n))
		return -EFAULT;
	buf[n] = '\0';
	if (kstrtouint(strim(buf), 0, &g_peek_offset))
		return -EINVAL;
	return n;
}

static int peek_open(struct inode *i, struct file *f)
{
	return single_open(f, peek_show, NULL);
}

static const struct proc_ops peek_ops = {
	.proc_open = peek_open, .proc_read = seq_read,
	.proc_lseek = seq_lseek, .proc_release = single_release,
	.proc_write = peek_write,
};

/* /proc/rodin_shared_hack/cpu_lut — dump all 32 LUT entries x 3 clusters
 * from CSRAM 0x0c0dd360/0x480/0x5a0 (mtk_cpufreq_hw CSRAM).
 * Each entry: u32 raw, low 12 bits = freq_field, freq_khz = freq_field * 1000.
 * Working entries: until "freq == prev_freq" (driver break condition).
 * Hidden entries: anything past that with different freq.
 */
static const struct {
	const char *name;
	u32 off;
} cpulut_clusters[3] = {
	{ "eff   (cpu0-3, retail max 2100)", CPULUT_OFF_PD0 },
	{ "perf  (cpu4-6, retail max 3000)", CPULUT_OFF_PD1 },
	{ "prime (cpu7,   retail max 3250)", CPULUT_OFF_PD2 },
};

static int cpu_lut_show(struct seq_file *m, void *v)
{
	int c, i;
	u32 raw, freq_field, freq_khz, prev_freq;
	int working_count, hidden_count;

	if (!cpulut_va) {
		seq_puts(m, "cpulut_va = NULL (ioremap failed)\n");
		return 0;
	}

	seq_printf(m, "CSRAM mapped: phys=0x%lx, va=%p, size=0x%x\n\n",
		CPULUT_PA, cpulut_va, CPULUT_SIZE);

	for (c = 0; c < 3; c++) {
		u32 cluster_off = cpulut_clusters[c].off;

		seq_printf(m, "=== Cluster %d: %s ===\n", c, cpulut_clusters[c].name);
		seq_puts(m, "  idx  raw         freq(MHz)  state\n");

		prev_freq = 0;
		working_count = 0;
		hidden_count = 0;

		for (i = 0; i < CPULUT_MAX_ENTRIES; i++) {
			raw = readl(cpulut_va + cluster_off + (i * 4));
			freq_field = raw & CPULUT_FREQ_MASK;
			freq_khz = freq_field * 1000;

			if (i == 0) {
				seq_printf(m, "  [%02d] 0x%08x  %5u      working\n",
					i, raw, freq_khz / 1000);
				working_count = 1;
			} else if (freq_khz == prev_freq) {
				/* driver would break here: working ends */
				if (working_count > 0 && hidden_count == 0) {
					seq_printf(m, "       --- driver break (freq == prev) ---\n");
				}
				seq_printf(m, "  [%02d] 0x%08x  %5u      pad (repeat)\n",
					i, raw, freq_khz / 1000);
			} else if (freq_khz == 0) {
				if (working_count > 0 && hidden_count == 0)
					seq_printf(m, "       --- working set ended ---\n");
				seq_printf(m, "  [%02d] 0x%08x  %5u      empty\n",
					i, raw, freq_khz / 1000);
			} else if (working_count > 0 && working_count == i) {
				seq_printf(m, "  [%02d] 0x%08x  %5u      working\n",
					i, raw, freq_khz / 1000);
				working_count++;
			} else {
				seq_printf(m, "  [%02d] 0x%08x  %5u      *** HIDDEN ***\n",
					i, raw, freq_khz / 1000);
				hidden_count++;
			}
			prev_freq = freq_khz;
		}
		seq_printf(m, "  -> working: %d entries, hidden: %d entries\n\n",
			working_count, hidden_count);
	}
	return 0;
}

static int cpu_lut_open(struct inode *i, struct file *f)
{
	return single_open(f, cpu_lut_show, NULL);
}

static const struct proc_ops cpu_lut_ops = {
	.proc_open = cpu_lut_open, .proc_read = seq_read,
	.proc_lseek = seq_lseek, .proc_release = single_release,
};

/* /proc/rodin_shared_hack/hbvc_safe — read ONLY the 4 offsets AP source
 * already reads safely (debug frontend/backend regs). Validates ioremap +
 * region accessibility before any sweep. If this prints values != 0xdeadbeef
 * == AP read access works, region not gated for reads in those slots. */
static int hbvc_safe_show(struct seq_file *m, void *v)
{
	if (!hbvc_va) {
		seq_puts(m, "hbvc_va = NULL (ioremap failed)\n");
		return 0;
	}
	seq_printf(m, "HBVC region: phys=0x%lx va=%p size=0x%x\n\n",
		HBVC_PA, hbvc_va, HBVC_SIZE);
	seq_printf(m, "  +0x400 FLL0_DBG_FRONTEND0 = 0x%08x\n",
		readl(hbvc_va + HBVC_OFF_FLL0_FRONTEND));
	seq_printf(m, "  +0x404 FLL1_DBG_FRONTEND0 = 0x%08x\n",
		readl(hbvc_va + HBVC_OFF_FLL1_FRONTEND));
	seq_printf(m, "  +0x480 GRP0_DBG_BACKEND0  = 0x%08x\n",
		readl(hbvc_va + HBVC_OFF_GRP0_BACKEND));
	seq_printf(m, "  +0x484 GRP1_DBG_BACKEND0  = 0x%08x\n",
		readl(hbvc_va + HBVC_OFF_GRP1_BACKEND));
	return 0;
}

static int hbvc_safe_open(struct inode *i, struct file *f)
{
	return single_open(f, hbvc_safe_show, NULL);
}

static const struct proc_ops hbvc_safe_ops = {
	.proc_open = hbvc_safe_open, .proc_read = seq_read,
	.proc_lseek = seq_lseek, .proc_release = single_release,
};

/* /proc/rodin_shared_hack/hbvc_dump — sweep 0x000..0xFFC, show non-zero u32s.
 * Risk: DEVAPC may abort on protected offsets. Catch via try/except via
 * readl alone (kernel will OOPS on bad read, but we accept that risk on
 * first probe — module reload recovers). */
static int hbvc_dump_show(struct seq_file *m, void *v)
{
	int off;
	u32 val;
	int total_nonzero = 0;
	if (!hbvc_va) {
		seq_puts(m, "hbvc_va = NULL\n");
		return 0;
	}
	seq_printf(m, "HBVC sweep (showing non-zero u32 u4-aligned):\n");
	for (off = 0; off < HBVC_SIZE; off += 4) {
		val = readl(hbvc_va + off);
		if (val) {
			seq_printf(m, "  +0x%03x = 0x%08x\n", off, val);
			total_nonzero++;
			if (total_nonzero > 200) {
				seq_puts(m, "  ... cap 200 hits\n");
				break;
			}
		}
	}
	seq_printf(m, "total non-zero: %d\n", total_nonzero);
	return 0;
}

static int hbvc_dump_open(struct inode *i, struct file *f)
{
	return single_open(f, hbvc_dump_show, NULL);
}

static const struct proc_ops hbvc_dump_ops = {
	.proc_open = hbvc_dump_open, .proc_read = seq_read,
	.proc_lseek = seq_lseek, .proc_release = single_release,
};

/* /proc/rodin_shared_hack/hbvc_write — write u32 at offset in HBVC region.
 * Format: "<hex_off> <hex_val>"
 * If DEVAPC blocks, write triggers violation logged in dmesg + /proc/devapc_dbg.
 * If permits, write goes directly to PMIF interface. */
static ssize_t hbvc_write(struct file *f, const char __user *ub,
			  size_t n, loff_t *o)
{
	char buf[64];
	u32 off = 0, val = 0;

	if (!hbvc_va)
		return -ENODEV;
	if (!n || n >= sizeof(buf))
		return -EINVAL;
	if (copy_from_user(buf, ub, n))
		return -EFAULT;
	buf[n] = '\0';
	if (sscanf(buf, "%x %x", &off, &val) != 2)
		return -EINVAL;
	if (off >= HBVC_SIZE - 3 || (off & 3))
		return -EINVAL;

	writel(val, hbvc_va + off);
	wmb();
	pr_info("rodin_shared_hack: HBVC write phys=0x%lx+0x%x = 0x%x\n",
		HBVC_PA, off, val);
	return n;
}

static int hbvc_write_show(struct seq_file *m, void *v)
{
	seq_puts(m, "write: \"<hex_off> <hex_val>\" — writes u32 to HBVC region\n");
	seq_puts(m, "Risk: DEVAPC violation possible. Monitor /proc/devapc_dbg + dmesg\n");
	return 0;
}

static int hbvc_write_open(struct inode *i, struct file *f)
{
	return single_open(f, hbvc_write_show, NULL);
}

static const struct proc_ops hbvc_write_ops = {
	.proc_open = hbvc_write_open, .proc_read = seq_read,
	.proc_lseek = seq_lseek, .proc_release = single_release,
	.proc_write = hbvc_write,
};

static struct proc_dir_entry *hack_dir;

static int __init rodin_shared_hack_init(void)
{
	shared_va = ioremap_wc(GPUEB_SHARED_PA, GPUFREQ_SHARED_SIZE);
	if (!shared_va) {
		pr_err("rodin_shared_hack: ioremap_wc(0x%lx) failed\n",
		       GPUEB_SHARED_PA);
		return -ENOMEM;
	}

	hack_dir = proc_mkdir("rodin_shared_hack", NULL);
	if (!hack_dir) {
		iounmap(shared_va);
		shared_va = NULL;
		return -ENOMEM;
	}
	proc_create("snap",      0444, hack_dir, &snap_ops);
	proc_create("test_mode", 0664, hack_dir, &test_mode_ops);
	proc_create("raw_write", 0664, hack_dir, &raw_ops);
	proc_create("find",      0664, hack_dir, &find_ops);
	proc_create("peek",      0664, hack_dir, &peek_ops);

	/* CSRAM CPU LUT mapping (read-only, dump only). Best effort: if it
	 * fails (DEVAPC or wrong addr), the gpufreq path still works. */
	cpulut_va = ioremap(CPULUT_PA, CPULUT_SIZE);
	if (cpulut_va) {
		proc_create("cpu_lut", 0444, hack_dir, &cpu_lut_ops);
		pr_info("rodin_shared_hack: cpulut mapped phys 0x%lx (size 0x%x)\n",
			CPULUT_PA, CPULUT_SIZE);
	} else {
		pr_warn("rodin_shared_hack: ioremap CSRAM 0x%lx failed (cpu_lut disabled)\n",
			CPULUT_PA);
	}

	/* MFG_HBVC mapping (read-only). DEVAPC risk on sweep — use hbvc_safe
	 * proc first (only the 4 AP-confirmed offsets), THEN hbvc_dump if safe. */
	hbvc_va = ioremap(HBVC_PA, HBVC_SIZE);
	if (hbvc_va) {
		proc_create("hbvc_safe",  0444, hack_dir, &hbvc_safe_ops);
		proc_create("hbvc_dump",  0444, hack_dir, &hbvc_dump_ops);
		proc_create("hbvc_write", 0664, hack_dir, &hbvc_write_ops);
		pr_info("rodin_shared_hack: hbvc mapped phys 0x%lx (size 0x%x)\n",
			HBVC_PA, HBVC_SIZE);
	} else {
		pr_warn("rodin_shared_hack: ioremap HBVC 0x%lx failed\n", HBVC_PA);
	}

	pr_info("rodin_shared_hack: mapped phys 0x%lx (size 0x%x), test_mode read = %u\n",
		GPUEB_SHARED_PA, GPUFREQ_SHARED_SIZE,
		readl(shared_va + OFF_TEST_MODE));
	return 0;
}

static void __exit rodin_shared_hack_exit(void)
{
	proc_remove(hack_dir);
	if (shared_va) {
		iounmap(shared_va);
		shared_va = NULL;
	}
	if (cpulut_va) {
		iounmap(cpulut_va);
		cpulut_va = NULL;
	}
	if (hbvc_va) {
		iounmap(hbvc_va);
		hbvc_va = NULL;
	}
}

module_init(rodin_shared_hack_init);
module_exit(rodin_shared_hack_exit);

MODULE_DESCRIPTION("rodin_shared_hack — direct GPUEB shared memory write (test_mode bypass)");
MODULE_AUTHOR("Kaua / Revenant");
MODULE_LICENSE("GPL v2");
