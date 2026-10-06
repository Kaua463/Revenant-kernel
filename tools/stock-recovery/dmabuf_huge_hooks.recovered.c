/* Hook recipe only: copy_page_range after vma_needs_copy succeeds,
 * before its is_cow/notifier/page-table walk. Not installed or exported.
 */
static void dmabuf_huge_fork_prepare(struct vm_area_struct *dst,
		struct vm_area_struct *src)
{
	if (src->vm_flags & (1UL << 39)) {
		split_dmabuf_huge_range(src);
		vm_flags_clear(src, 1UL << 39);
		vm_flags_clear(dst, 1UL << 39);
	}
}
