// SPDX-License-Identifier: GPL-2.0-only
/* NEW RAM-only DMA-BUF exporter for disposable VM, not Xiaomi/shipping code. */
#include <linux/atomic.h>
#include <linux/capability.h>
#include <linux/dma-buf.h>
#include <linux/dma-mapping.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/miscdevice.h>
#include <linux/mm.h>
#include <linux/mmap_lock.h>
#include <linux/module.h>
#include <linux/pgtable.h>
#include <linux/scatterlist.h>
#include <linux/slab.h>
#include <linux/xiaomi_dmabuf_huge.h>
#include "audit-map-contract.h"
#include "audit-export-contract.h"

#if defined(MODULE) || !defined(CONFIG_XIAOMI_DMABUF_RUNTIME_AUDIT) || \
    !defined(CONFIG_XIAOMI_DMABUF_HUGETLB) || !defined(CONFIG_ARM64_4K_PAGES) || \
    !defined(CONFIG_ARM64_VA_BITS_39) || !defined(CONFIG_DMA_SHARED_BUFFER)
#error "Disposable built-in ARM64/4K/VA39 DMA-BUF audit only"
#endif
#if CONFIG_PGTABLE_LEVELS != 3
#error "Three-level page tables required"
#endif

#define EXPORT_BYTES (2UL * DMA_AUDIT_BLOCK_BYTES)
#define EXPORT_ORDER 10
#define EXPORT_MAX_LIVE 8

struct export_buffer {
	struct page *pages;
	unsigned long long id;
	unsigned int mode;
};

static atomic_t export_live = ATOMIC_INIT(0);
static atomic64_t export_next_id = ATOMIC64_INIT(0);
static struct miscdevice dma_export_audit_device;
int recovered_dma_audit_plain_remap(struct vm_area_struct *, unsigned long, unsigned int);

static struct sg_table *export_map(struct dma_buf_attachment *attachment,
		enum dma_data_direction direction)
{
	struct export_buffer *buffer = attachment->dmabuf->priv;
	struct sg_table *table = kzalloc(sizeof(*table), GFP_KERNEL);
	int error;

	if (!table)
		return ERR_PTR(-ENOMEM);
	error = sg_alloc_table(table, 1, GFP_KERNEL);
	if (error)
		goto free_table;
	sg_set_page(table->sgl, buffer->pages, EXPORT_BYTES, 0);
	error = dma_map_sgtable(attachment->dev, table, direction, 0);
	if (error)
		goto free_sg;
	return table;
free_sg:
	sg_free_table(table);
free_table:
	kfree(table);
	return ERR_PTR(error);
}

static void export_unmap(struct dma_buf_attachment *attachment,
		struct sg_table *table, enum dma_data_direction direction)
{
	dma_unmap_sgtable(attachment->dev, table, direction, 0);
	sg_free_table(table);
	kfree(table);
}

static void dma_export_audit_release(struct dma_buf *dmabuf)
{
	struct export_buffer *buffer = dmabuf->priv;
	unsigned long long id = buffer->id;
	unsigned int mode = buffer->mode;

	__free_pages(buffer->pages, EXPORT_ORDER);
	kfree(buffer);
	pr_info("DMA_EXPORT_RELEASE id=%llu mode=%u\n", id, mode);
	/* Query reaches zero only after both frees and the release event. */
	atomic_dec(&export_live);
}

static bool export_empty_destination(struct vm_area_struct *vma)
{
	unsigned long address;

	mmap_assert_write_locked(vma->vm_mm);
	for (address = vma->vm_start; address < vma->vm_end;
	     address += DMA_AUDIT_BLOCK_BYTES) {
		pgd_t *pgd = pgd_offset(vma->vm_mm, address);
		p4d_t *p4d;
		pud_t *pud;
		pmd_t *pmd;

		if (pgd_none(*pgd))
			continue;
		if (pgd_bad(*pgd))
			return false;
		p4d = p4d_offset(pgd, address);
		if (p4d_none(*p4d))
			continue;
		if (p4d_bad(*p4d))
			return false;
		pud = pud_offset(p4d, address);
		if (pud_none(*pud))
			continue;
		if (pud_bad(*pud))
			return false;
		pmd = pmd_offset(pud, address);
		if (!pmd_none(*pmd))
			return false;
	}
	return true;
}

static int dma_export_audit_mmap(struct dma_buf *dmabuf, struct vm_area_struct *vma)
{
	struct export_buffer *buffer = dmabuf->priv;
	unsigned long length = vma->vm_end - vma->vm_start;
	unsigned long offset, pfn;
	int result;

	mmap_assert_write_locked(vma->vm_mm);
	if (!(vma->vm_flags & VM_SHARED) || vma->vm_flags & VM_EXEC)
		return -EPERM;
	if (vma->vm_pgoff > (ULONG_MAX >> PAGE_SHIFT))
		return -EINVAL;
	offset = vma->vm_pgoff << PAGE_SHIFT;
	if (!length || offset > EXPORT_BYTES || length > EXPORT_BYTES - offset)
		return -EINVAL;
	pfn = page_to_pfn(buffer->pages) + (offset >> PAGE_SHIFT);
	if (length >= DMA_AUDIT_BLOCK_BYTES &&
	    (dma_audit_map_check(vma->vm_start, vma->vm_end,
			page_to_phys(buffer->pages), EXPORT_BYTES, offset,
			true, true) != DMA_AUDIT_MAP_OK ||
	     !export_empty_destination(vma)))
		return -EINVAL;
	vm_flags_clear(vma, VM_MAYEXEC);
	if (length < DMA_AUDIT_BLOCK_BYTES)
		result = remap_pfn_range(vma, vma->vm_start, pfn, length,
				vma->vm_page_prot);
	else
		result = recovered_dma_audit_plain_remap(vma, pfn, buffer->mode);
	pr_info("DMA_EXPORT_MMAP id=%llu mode=%u bytes=%lu offset=%lu huge=%u result=%d\n",
		buffer->id, buffer->mode, length, offset,
		(unsigned int)(length >= DMA_AUDIT_BLOCK_BYTES), result);
	return result;
}

static const struct dma_buf_ops dma_export_audit_ops = {
	.map_dma_buf = export_map,
	.unmap_dma_buf = export_unmap,
	.release = dma_export_audit_release,
	.mmap = dma_export_audit_mmap,
};

static int export_open(struct inode *inode, struct file *file)
{
	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	return file->private_data == &dma_export_audit_device ? 0 : -ENODEV;
}

static long dma_export_audit_ioctl(struct file *file, unsigned int command, unsigned long argument)
{
	DEFINE_DMA_BUF_EXPORT_INFO(info);
	struct export_buffer *buffer;
	struct dma_buf *dmabuf;
	int fd;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	if (file->private_data != &dma_export_audit_device)
		return -ENODEV;
	if (argument || (command != DMA_AUDIT_EXPORT_PMD &&
			 command != DMA_AUDIT_EXPORT_PTE && command != DMA_AUDIT_EXPORT_LIVE))
		return -EINVAL;
	if (command == DMA_AUDIT_EXPORT_LIVE)
		return atomic_read(&export_live);
	if (atomic_inc_return(&export_live) > EXPORT_MAX_LIVE) {
		atomic_dec(&export_live);
		return -ENOSPC;
	}
	buffer = kzalloc(sizeof(*buffer), GFP_KERNEL);
	if (!buffer) {
		atomic_dec(&export_live);
		return -ENOMEM;
	}
	buffer->pages = alloc_pages(GFP_KERNEL | __GFP_ZERO | __GFP_COMP |
				    __GFP_NOWARN, EXPORT_ORDER);
	if (!buffer->pages) {
		kfree(buffer);
		atomic_dec(&export_live);
		return -ENOMEM;
	}
	buffer->id = (unsigned long long)atomic64_inc_return(&export_next_id);
	buffer->mode = command == DMA_AUDIT_EXPORT_PTE;
	info.exp_name = "recovered-dma-vm";
	info.ops = &dma_export_audit_ops;
	info.size = EXPORT_BYTES;
	info.flags = O_RDWR;
	info.priv = buffer;
	dmabuf = dma_buf_export(&info);
	if (IS_ERR(dmabuf)) {
		fd = PTR_ERR(dmabuf);
		__free_pages(buffer->pages, EXPORT_ORDER);
		kfree(buffer);
		atomic_dec(&export_live);
		return fd;
	}
	pr_info("DMA_EXPORT_ALLOC id=%llu mode=%u bytes=%lu\n",
		buffer->id, buffer->mode, (unsigned long)EXPORT_BYTES);
	fd = dma_buf_fd(dmabuf, O_CLOEXEC);
	if (fd < 0)
		dma_buf_put(dmabuf);
	return fd;
}

static const struct file_operations dma_export_audit_factory_fops = {
	.owner = THIS_MODULE,
	.open = export_open,
	.unlocked_ioctl = dma_export_audit_ioctl,
	.compat_ioctl = dma_export_audit_ioctl, /* Fixed _IO commands, no pointer argument. */
	.llseek = no_llseek,
};

static struct miscdevice dma_export_audit_device = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "recovered-dma-export-audit",
	.fops = &dma_export_audit_factory_fops,
	.mode = 0600,
};

static int __init export_init(void)
{
	return misc_register(&dma_export_audit_device);
}
device_initcall(export_init);
