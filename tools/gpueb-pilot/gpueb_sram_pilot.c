// SPDX-License-Identifier: GPL-2.0-only
/* Deliberately limited rodin GPUEB SRAM read pilot. No MMIO writes. */
#include <linux/errno.h>
#include <linux/capability.h>
#include <asm/byteorder.h>
#include <linux/io.h>
#include <linux/ioport.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/proc_fs.h>
#include <linux/sizes.h>
#include <linux/uaccess.h>

#define GPUEB_BASE 0x13c00000ULL
#define GPUEB_WINDOW 0x50000ULL
#define PILOT_SIZE 64U
#define FIRST_REG 0x13c4fd1cULL
#define GPR_SIZE 0x64ULL
#define MAILBOX_BASE 0x13c4fd80ULL
#define MAILBOX_SIZE 0x280ULL

static struct proc_dir_entry *pilot_entry;
static DEFINE_MUTEX(pilot_lock);
static __le32 snapshot[PILOT_SIZE / sizeof(u32)];
static bool snapshot_valid;

static ssize_t pilot_read(struct file *file, char __user *user_buf,
			  size_t count, loff_t *pos)
{
	void __iomem *mapped;
	unsigned int i;
	ssize_t result;

	if (!capable(CAP_SYS_RAWIO))
		return -EPERM;
	if (*pos < 0)
		return -EINVAL;
	if (!count || *pos >= PILOT_SIZE)
		return 0;

	/* One hardware capture per module load, including concurrent opens. */
	if (mutex_lock_interruptible(&pilot_lock))
		return -ERESTARTSYS;
	if (snapshot_valid)
		goto copy;

	/* Never map any GPR, mailbox or unknown tail. */
	BUILD_BUG_ON(GPUEB_BASE + SZ_4K > FIRST_REG);
	BUILD_BUG_ON(PILOT_SIZE > SZ_4K);
	BUILD_BUG_ON(GPUEB_BASE % sizeof(u32));
	BUILD_BUG_ON(PILOT_SIZE % sizeof(u32));
	mapped = ioremap(GPUEB_BASE, SZ_4K);
	if (!mapped) {
		result = -ENXIO;
		goto unlock;
	}
	/* Match the aligned word accesses observed in this ROM's LK. */
	for (i = 0; i < ARRAY_SIZE(snapshot); i++)
		snapshot[i] = cpu_to_le32(readl(mapped + i * sizeof(u32)));
	iounmap(mapped);
	snapshot_valid = true;

copy:
	result = simple_read_from_buffer(user_buf, count, pos,
					snapshot, sizeof(snapshot));
unlock:
	mutex_unlock(&pilot_lock);
	return result;
}

static const struct proc_ops pilot_ops = {
	.proc_read = pilot_read,
	.proc_lseek = no_llseek,
};

static int __init pilot_init(void)
{
	struct device_node *node;
	struct resource resource;
	int result;

	node = of_find_compatible_node(NULL, NULL, "mediatek,gpueb");
	if (!node)
		return -ENODEV;
	if (!of_device_is_available(node)) {
		result = -ENODEV;
		goto put_node;
	}
	if (of_property_match_string(node, "reg-names", "gpueb_base") != 0 ||
	    of_property_match_string(node, "reg-names", "gpueb_gpr_base") != 1 ||
	    of_property_match_string(node, "reg-names", "mbox0_base") != 4) {
		result = -ENODEV;
		goto put_node;
	}
	result = of_address_to_resource(node, 0, &resource);
	if (result || resource.start != GPUEB_BASE ||
	    resource_size(&resource) != GPUEB_WINDOW) {
		result = -ENODEV;
		goto put_node;
	}
	result = of_address_to_resource(node, 1, &resource);
	if (result || resource.start != FIRST_REG ||
	    resource_size(&resource) != GPR_SIZE) {
		result = -ENODEV;
		goto put_node;
	}
	result = of_address_to_resource(node, 4, &resource);
	if (result || resource.start != MAILBOX_BASE ||
	    resource_size(&resource) != MAILBOX_SIZE)
		result = -ENODEV;
put_node:
	of_node_put(node);
	if (result)
		return result;

	pilot_entry = proc_create("gpueb_sram_pilot", 0400, NULL, &pilot_ops);
	return pilot_entry ? 0 : -ENOMEM;
}

static void __exit pilot_exit(void)
{
	proc_remove(pilot_entry);
}

module_init(pilot_init);
module_exit(pilot_exit);
MODULE_LICENSE("GPL");
MODULE_VERSION("2");
MODULE_DESCRIPTION("Bounded read-only GPUEB SRAM pilot for rodin");
