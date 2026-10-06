/* Review-only stock ARM64 4K/VA39 address selector reconstruction.
 * Exact Image 99485b0132e3aa28f4e965119591c8149fe3c20e7e0fd10d753ef014a582472e.
 * Not integrated: helper-trace equivalence is not allocator/lifetime proof.
 * Unlike generic ACK: size-dependent alignment, prev->vm_end (no grow-up gap),
 * top-down low=max(PAGE_SIZE,mmap_min_addr), fallback low=mm->mmap_base.
 */
static unsigned long dma_buf_hugetlb_get_unmapped_area(struct file *file,
		unsigned long addr, unsigned long len, unsigned long pgoff,
		unsigned long flags)
{
	struct mm_struct *mm = current->mm;
	struct vm_area_struct *vma, *prev;
	struct vm_unmapped_area_info info;
	unsigned long end = TASK_SIZE;
	unsigned long mask = len >> 21 ? 0x1fffffUL :
			     len >> 16 ? 0xffffUL : 0;
	unsigned long hint_mask = mask ? mask : 0xfffUL;

	(void)file;
	(void)pgoff;
	if (len > end - mmap_min_addr)
		return -ENOMEM;
	if (flags & MAP_FIXED)
		return addr;
	if (addr) {
		addr = (addr + hint_mask) & ~hint_mask;
		vma = find_vma_prev(mm, addr, &prev);
		if (end - len >= addr && addr >= mmap_min_addr &&
		    (!vma || addr + len <= vm_start_gap(vma)) &&
		    (!prev || addr >= prev->vm_end))
			return addr;
	}
	info.length = len;
	info.align_mask = mask;
	info.align_offset = 0;
	if (mm->get_unmapped_area != arch_get_unmapped_area_topdown) {
		info.flags = 0;
		info.low_limit = mm->mmap_base;
		info.high_limit = TASK_SIZE;
		return vm_unmapped_area(&info);
	}
	info.flags = VM_UNMAPPED_AREA_TOPDOWN;
	info.low_limit = mmap_min_addr > PAGE_SIZE ? mmap_min_addr : PAGE_SIZE;
	info.high_limit = mm->mmap_base;
	/* Raw stock branch retained, including compat high-address arithmetic.
	 * Valid outer VFS checks may exclude parts; do not delete from recovery.
	 */
	if (addr > TASK_SIZE)
		info.high_limit += TASK_SIZE +
			(TASK_SIZE == 0x8000000000UL ? 0xffffff8000000000UL :
			 0xffffffff00001000UL);
	addr = vm_unmapped_area(&info);
	if (addr & 0xfffUL) {
		info.flags = 0;
		info.low_limit = mm->mmap_base;
		info.high_limit = TASK_SIZE;
		addr = vm_unmapped_area(&info);
	}
	return addr;
}
