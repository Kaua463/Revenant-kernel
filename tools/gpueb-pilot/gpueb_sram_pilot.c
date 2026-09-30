// SPDX-License-Identifier: GPL-2.0-only
/* Deliberately limited rodin GPUEB SRAM read pilot. No MMIO writes. */
#include <linux/errno.h>
#include <linux/io.h>
#include <linux/ioport.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/proc_fs.h>
#include <linux/sizes.h>
#include <linux/uaccess.h>

#define GPUEB_BASE 0x13c00000ULL
#define GPUEB_WINDOW 0x50000ULL
#define PILOT_SIZE 64U
#define FIRST_REG 0x13c4fd1cULL

static struct proc_dir_entry *pilot_entry;

static ssize_t pilot_read(struct file *file, char __user *user_buf,
			  size_t count, loff_t *pos)
{
	u8 data[PILOT_SIZE];
	void __iomem *mapped;
	unsigned int i;
	ssize_t result;

	if (*pos >= PILOT_SIZE)
		return 0;

	/* Never map any GPR, mailbox or unknown tail. */
	BUILD_BUG_ON(GPUEB_BASE + SZ_4K > FIRST_REG);
	mapped = ioremap(GPUEB_BASE, SZ_4K);
	if (!mapped)
		return -ENXIO;
	for (i = 0; i < PILOT_SIZE; i++)
		data[i] = readb(mapped + i);
	iounmap(mapped);

	result = simple_read_from_buffer(user_buf, count, pos, data, sizeof(data));
	return result;
}

static const struct proc_ops pilot_ops = {
	.proc_read = pilot_read,
	.proc_lseek = default_llseek,
};

static int __init pilot_init(void)
{
	struct device_node *node;
	struct resource resource;
	int result;

	node = of_find_compatible_node(NULL, NULL, "mediatek,gpueb");
	if (!node)
		return -ENODEV;
	result = of_address_to_resource(node, 0, &resource);
	of_node_put(node);
	if (result || resource.start != GPUEB_BASE ||
	    resource_size(&resource) != GPUEB_WINDOW)
		return -ENODEV;

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
MODULE_DESCRIPTION("Bounded read-only GPUEB SRAM pilot for rodin");
