// SPDX-License-Identifier: GPL-2.0-only
/* NEW disposable-VM producer. Not Xiaomi code; never a phone module. */
#include <linux/atomic.h>
#include <linux/capability.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/miscdevice.h>
#include <linux/mm.h>
#include <linux/mmap_lock.h>
#include <linux/module.h>
#include <linux/pgtable.h>
#include <linux/printk.h>
#include <linux/slab.h>
#include <linux/xiaomi_dmabuf_huge.h>

#include "audit-map-contract.h"

#if defined(MODULE) || !defined(CONFIG_XIAOMI_DMABUF_RUNTIME_AUDIT) || \
    !defined(CONFIG_XIAOMI_DMABUF_HUGETLB) || !defined(CONFIG_ARM64) || \
    !defined(CONFIG_ARM64_4K_PAGES) || !defined(CONFIG_ARM64_VA_BITS_39)
#error "Disposable ARM64/4K/VA39 built-in audit only"
#endif
#if CONFIG_PGTABLE_LEVELS != 3
#error "Recovered mapper requires three-level page tables"
#endif

#define AUDIT_BYTES (2UL * DMA_AUDIT_BLOCK_BYTES)
#define AUDIT_ORDER 10 /* 4 MiB with 4 KiB base pages */

struct audit_buffer {
	struct page *pages;
	unsigned int map_type;
	unsigned long long id;
};

static atomic64_t audit_next_id = ATOMIC64_INIT(0);
static struct miscdevice audit_pmd_device;
static struct miscdevice audit_pte_device;

static int audit_open(struct inode *inode, struct file *file)
{
	struct miscdevice *device = file->private_data;
	struct audit_buffer *buffer;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	if (device != &audit_pmd_device && device != &audit_pte_device)
		return -ENODEV;
	buffer = kzalloc(sizeof(*buffer), GFP_KERNEL);
	if (!buffer)
		return -ENOMEM;
	buffer->pages = alloc_pages(GFP_KERNEL | __GFP_ZERO | __GFP_COMP |
				    __GFP_NOWARN, AUDIT_ORDER);
	if (!buffer->pages) {
		kfree(buffer);
		return -ENOMEM;
	}
	buffer->map_type = device == &audit_pte_device;
	buffer->id = (unsigned long long)atomic64_inc_return(&audit_next_id);
	file->private_data = buffer;
	pr_info("DMA_AUDIT_ALLOC id=%llu mode=%u bytes=%lu\n",
		buffer->id, buffer->map_type, AUDIT_BYTES);
	return 0;
}

static int audit_release(struct inode *inode, struct file *file)
{
	struct audit_buffer *buffer = file->private_data;
	unsigned long long id = buffer->id;
	unsigned int map_type = buffer->map_type;

	/* File-owned, not VMA-callback-owned. Last fput only, after mappings go. */
	__free_pages(buffer->pages, AUDIT_ORDER);
	kfree(buffer);
	/* Log after both real frees return; never dereference freed storage. */
	pr_info("DMA_AUDIT_RELEASE id=%llu mode=%u\n", id, map_type);
	return 0;
}

static bool audit_empty_destination(struct vm_area_struct *vma)
{
	struct mm_struct *mm = vma->vm_mm;
	unsigned long address;

	mmap_assert_write_locked(mm);
	for (address = vma->vm_start; address < vma->vm_end;
	     address += DMA_AUDIT_BLOCK_BYTES) {
		pgd_t *pgd = pgd_offset(mm, address);
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
		/* Reject even an allocated-but-empty PTE table: never overwrite it. */
		if (!pmd_none(*pmd))
			return false;
	}
	return true;
}

static int audit_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct audit_buffer *buffer = file->private_data;
	unsigned long offset;
	phys_addr_t physical = page_to_phys(buffer->pages);
	enum dma_audit_map_reason reason;

	mmap_assert_write_locked(vma->vm_mm);
	if (vma->vm_flags & VM_EXEC)
		return -EPERM;
	if (vma->vm_pgoff > (ULONG_MAX >> PAGE_SHIFT))
		return -EINVAL;
	offset = vma->vm_pgoff << PAGE_SHIFT;
	/* First scalar check only. 'true' here does not claim real emptiness. */
	reason = dma_audit_map_check(vma->vm_start, vma->vm_end, physical,
			AUDIT_BYTES, offset, !!(vma->vm_flags & VM_SHARED), true);
	if (reason != DMA_AUDIT_MAP_OK)
		return -EINVAL;
	if (!audit_empty_destination(vma))
		return -EBUSY;
	vm_flags_clear(vma, VM_MAYEXEC);
	/* No .open/.close refs: failed mmap has no balancing vma_close.
	 * mmap syscall fget holds file-owned backing across partial-map unwind.
	 * Keep vm_file unchanged; split/fork/move use ordinary file references.
	 * Real MMU/SMP and ENOMEM unwind still require disposable guest tests.
	 */
	return dmabuf_huge_remap_pfn_range(vma, vma->vm_start,
			page_to_pfn(buffer->pages) + (offset >> PAGE_SHIFT),
			vma->vm_end - vma->vm_start, vma->vm_page_prot,
			buffer->map_type);
}

static const struct file_operations audit_fops = {
	.owner = THIS_MODULE,
	.open = audit_open,
	.release = audit_release,
	.mmap = audit_mmap,
	.llseek = no_llseek,
};

static struct miscdevice audit_pmd_device = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "recovered-dma-audit-pmd",
	.fops = &audit_fops,
	.mode = 0600,
};

static struct miscdevice audit_pte_device = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "recovered-dma-audit-pte",
	.fops = &audit_fops,
	.mode = 0600,
};

static int __init audit_init(void)
{
	int error = misc_register(&audit_pmd_device);

	if (error)
		return error;
	error = misc_register(&audit_pte_device);
	if (error)
		misc_deregister(&audit_pmd_device);
	return error;
}
device_initcall(audit_init);
