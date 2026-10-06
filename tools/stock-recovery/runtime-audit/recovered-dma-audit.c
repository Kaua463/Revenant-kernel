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
#include <linux/mutex.h>
#include <linux/pgtable.h>
#include <linux/printk.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/xiaomi_dmabuf_huge.h>

#include "audit-map-contract.h"
#include "audit-fault-plan.h"

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
	bool fault_pending;
	unsigned int fault_ordinal;
	bool unwind_pending;
	unsigned long unwind_mm_token;
	unsigned long unwind_task_token;
	unsigned long table_bytes_before;
	unsigned long table_bytes_partial;
};

static atomic64_t audit_next_id = ATOMIC64_INIT(0);
static DEFINE_MUTEX(audit_fault_mutex);
static struct dma_audit_fault_plan audit_fault_plan;
static unsigned long long audit_fault_id;
static unsigned int audit_fault_mode;
static s64 audit_fault_maps_before;
static struct vm_area_struct *audit_fault_vma;
static unsigned long audit_fault_first_pfn;
static struct audit_buffer *audit_fault_buffer;
extern atomic64_t dmabuf_hugetlb_pmd_map;
extern atomic64_t dmabuf_hugetlb_contpte_map;

/* Built-in audit link only, not exported or available in shipping kernels. */
bool recovered_dma_audit_fail_alloc(struct mm_struct *mm, unsigned int map_type);
bool recovered_dma_audit_fail_pmd_table(struct mm_struct *mm, unsigned int map_type);
int recovered_dma_audit_plain_remap(struct vm_area_struct *vma,
		unsigned long pfn, unsigned int map_type);

/* CPU-only DMA-BUF exporter shares the scoped fault-site mutex. The caller
 * validates owned extent and empty destination before reaching this helper.
 * No global allocator fault can leak into another audit mapping.
 */
int recovered_dma_audit_plain_remap(struct vm_area_struct *vma,
		unsigned long pfn, unsigned int map_type)
{
	int result;

	mmap_assert_write_locked(vma->vm_mm);
	mutex_lock(&audit_fault_mutex);
	result = dmabuf_huge_remap_pfn_range(vma, vma->vm_start, pfn,
			vma->vm_end - vma->vm_start, vma->vm_page_prot, map_type);
	mutex_unlock(&audit_fault_mutex);
	return result;
}

static bool audit_first_block_present(unsigned int map_type)
{
	struct vm_area_struct *vma = audit_fault_vma;
	unsigned long address = vma->vm_start;
	pgd_t *pgd = pgd_offset(vma->vm_mm, address);
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;
	unsigned int index;

	mmap_assert_write_locked(vma->vm_mm);
	if (pgd_none(*pgd) || pgd_bad(*pgd))
		return false;
	p4d = p4d_offset(pgd, address);
	if (p4d_none(*p4d) || p4d_bad(*p4d))
		return false;
	pud = pud_offset(p4d, address);
	if (pud_none(*pud) || pud_bad(*pud))
		return false;
	pmd = pmd_offset(pud, address);
	if (!map_type)
		return pmd_present(*pmd) && pmd_trans_huge(*pmd) &&
			pmd_pfn(*pmd) == audit_fault_first_pfn;
	if (pmd_none(*pmd) || pmd_bad(*pmd) || pmd_trans_huge(*pmd))
		return false;
	pte = pte_offset_kernel(pmd, address);
	for (index = 0; index < DMA_AUDIT_BLOCK_BYTES / PAGE_SIZE; index++)
		if (!pte_present(pte[index]) || !pte_special(pte[index]) ||
		    pte_pfn(pte[index]) != audit_fault_first_pfn + index)
			return false;
	return true;
}

/* A cold-PUD allocation must not consume a leaf-only fault ordinal. This site
 * is currently dormant in the guest: PMD-table arm/workload is a separate gate.
 */
bool recovered_dma_audit_fail_pmd_table(struct mm_struct *mm, unsigned int map_type)
{
	lockdep_assert_held(&audit_fault_mutex);
	if (map_type != audit_fault_mode ||
	    !dma_audit_fault_check_site(&audit_fault_plan, (unsigned long)current,
			(unsigned long)mm, DMA_AUDIT_FAULT_PMD_TABLE))
		return false;
	return true;
}

bool recovered_dma_audit_fail_alloc(struct mm_struct *mm, unsigned int map_type)
{
	s64 published;
	unsigned int table_present;

	lockdep_assert_held(&audit_fault_mutex);
	if (map_type != audit_fault_mode ||
	    !dma_audit_fault_check(&audit_fault_plan, (unsigned long)current,
				 (unsigned long)mm))
		return false;
	published = atomic64_read(map_type ? &dmabuf_hugetlb_contpte_map :
				 &dmabuf_hugetlb_pmd_map) - audit_fault_maps_before;
	table_present = audit_first_block_present(map_type);
	audit_fault_buffer->table_bytes_partial = mm_pgtables_bytes(mm);
	if (published != audit_fault_plan.ordinal - 1 ||
	    table_present != (audit_fault_plan.ordinal == 2))
		pr_err("DMA_AUDIT_FAULT_FAIL: partial-map count=%lld table=%u\n", published, table_present);
	pr_info("DMA_AUDIT_FAULT id=%llu mode=%u ordinal=%u published=%lld table=%u\n",
		audit_fault_id, map_type, audit_fault_plan.ordinal, published, table_present);
	return true;
}

static struct miscdevice audit_pmd_device;
static struct miscdevice audit_pte_device;
static struct miscdevice audit_fault_pmd_device;
static struct miscdevice audit_fault_pte_device;
static struct miscdevice audit_first_pmd_device;
static struct miscdevice audit_first_pte_device;

static int audit_open(struct inode *inode, struct file *file)
{
	struct miscdevice *device = file->private_data;
	struct audit_buffer *buffer;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	if (device != &audit_pmd_device && device != &audit_pte_device &&
	    device != &audit_fault_pmd_device && device != &audit_fault_pte_device &&
	    device != &audit_first_pmd_device && device != &audit_first_pte_device)
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
	buffer->map_type = device == &audit_pte_device || device == &audit_fault_pte_device ||
		device == &audit_first_pte_device;
	buffer->fault_ordinal = device == &audit_first_pmd_device ||
		device == &audit_first_pte_device ? 1 : 2;
	buffer->fault_pending = device == &audit_fault_pmd_device || device == &audit_fault_pte_device ||
		device == &audit_first_pmd_device || device == &audit_first_pte_device;
	buffer->id = (unsigned long long)atomic64_inc_return(&audit_next_id);
	file->private_data = buffer;
	pr_info("DMA_AUDIT_ALLOC id=%llu mode=%u bytes=%lu fault=%u\n",
		buffer->id, buffer->map_type, (unsigned long)AUDIT_BYTES,
		(unsigned int)buffer->fault_pending);
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
	bool inject;
	unsigned long table_bytes_retry;
	int result;

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
	/* Serialize audit remaps only. No global allocator failure or ioctl. */
	mutex_lock(&audit_fault_mutex);
	if (buffer->unwind_pending) {
		/* No saved pointer is dereferenced: the bounded guest retries in
		 * the same live task/mm, before creating any worker threads.
		 */
		if (buffer->unwind_mm_token != (unsigned long)vma->vm_mm ||
		    buffer->unwind_task_token != (unsigned long)current) {
			pr_err("DMA_AUDIT_ACCOUNTING_FAIL: retry context changed\n");
			mutex_unlock(&audit_fault_mutex);
			return -EINVAL;
		}
		table_bytes_retry = mm_pgtables_bytes(vma->vm_mm);
		if (table_bytes_retry != buffer->table_bytes_before ||
		    buffer->table_bytes_partial < buffer->table_bytes_before ||
		    (buffer->fault_ordinal == 1 ?
		     (buffer->table_bytes_partial != buffer->table_bytes_before &&
		      buffer->table_bytes_partial - buffer->table_bytes_before != PAGE_SIZE) :
		     (buffer->table_bytes_partial - buffer->table_bytes_before != PAGE_SIZE &&
		      buffer->table_bytes_partial - buffer->table_bytes_before != 2 * PAGE_SIZE))) {
			pr_err("DMA_AUDIT_ACCOUNTING_FAIL: table bytes before=%lu partial=%lu retry=%lu\n",
				buffer->table_bytes_before, buffer->table_bytes_partial, table_bytes_retry);
			mutex_unlock(&audit_fault_mutex);
			return -EINVAL;
		}
		pr_info("DMA_AUDIT_UNWIND id=%llu mode=%u before=%lu partial=%lu retry=%lu\n",
			buffer->id, buffer->map_type, buffer->table_bytes_before,
			buffer->table_bytes_partial, table_bytes_retry);
		buffer->unwind_pending = false;
	}
	inject = buffer->fault_pending;
	buffer->fault_pending = false;
	audit_fault_mode = buffer->map_type;
	audit_fault_id = buffer->id;
	if (inject) {
		audit_fault_buffer = buffer;
		buffer->table_bytes_before = mm_pgtables_bytes(vma->vm_mm);
		buffer->table_bytes_partial = 0;
		buffer->unwind_mm_token = (unsigned long)vma->vm_mm;
		buffer->unwind_task_token = (unsigned long)current;
		audit_fault_vma = vma;
		audit_fault_first_pfn = page_to_pfn(buffer->pages) + (offset >> PAGE_SHIFT);
		if (!dma_audit_fault_arm(&audit_fault_plan, (unsigned long)current,
					(unsigned long)vma->vm_mm, buffer->fault_ordinal)) {
			audit_fault_vma = NULL;
			audit_fault_buffer = NULL;
			mutex_unlock(&audit_fault_mutex);
			return -EINVAL;
		}
		audit_fault_maps_before = atomic64_read(buffer->map_type ?
			&dmabuf_hugetlb_contpte_map : &dmabuf_hugetlb_pmd_map);
	}
	result = dmabuf_huge_remap_pfn_range(vma, vma->vm_start,
			page_to_pfn(buffer->pages) + (offset >> PAGE_SHIFT),
			vma->vm_end - vma->vm_start, vma->vm_page_prot,
			buffer->map_type);
	if (inject)
		pr_info("DMA_AUDIT_FAULT_RETURN id=%llu mode=%u result=%d fired=%u\n",
			buffer->id, buffer->map_type, result, audit_fault_plan.fired);
	if (inject && result == -ENOMEM && audit_fault_plan.fired == 1)
		buffer->unwind_pending = true;
	audit_fault_plan = (struct dma_audit_fault_plan){0};
	audit_fault_vma = NULL;
	audit_fault_buffer = NULL;
	mutex_unlock(&audit_fault_mutex);
	return result;
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

static struct miscdevice audit_fault_pmd_device = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "recovered-dma-audit-fault-pmd",
	.fops = &audit_fops,
	.mode = 0600,
};

static struct miscdevice audit_fault_pte_device = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "recovered-dma-audit-fault-pte",
	.fops = &audit_fops,
	.mode = 0600,
};

static struct miscdevice audit_first_pmd_device = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "recovered-dma-audit-first-pmd",
	.fops = &audit_fops,
	.mode = 0600,
};

static struct miscdevice audit_first_pte_device = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "recovered-dma-audit-first-pte",
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
		goto undo_pmd;
	error = misc_register(&audit_fault_pmd_device);
	if (error)
		goto undo_pte;
	error = misc_register(&audit_fault_pte_device);
	if (error)
		goto undo_fault_pmd;
	error = misc_register(&audit_first_pmd_device);
	if (error)
		goto undo_fault_pte;
	error = misc_register(&audit_first_pte_device);
	if (error)
		goto undo_first_pmd;
	return 0;
undo_first_pmd:
	misc_deregister(&audit_first_pmd_device);
undo_fault_pte:
	misc_deregister(&audit_fault_pte_device);
undo_fault_pmd:
	misc_deregister(&audit_fault_pmd_device);
undo_pte:
	misc_deregister(&audit_pte_device);
undo_pmd:
	misc_deregister(&audit_pmd_device);
	return error;
}
device_initcall(audit_init);
