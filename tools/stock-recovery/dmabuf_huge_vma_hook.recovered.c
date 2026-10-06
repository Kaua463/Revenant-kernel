/* Review-only VMA boundary-change recipe; caller must hold its VMA write
 * lock and finish vma_prepare first. All observed callers pass adj_next=0.
 * Does not replace allocation, maple-tree or VMA lifetime management.
 */
static void dmabuf_huge_adjust_prepare(struct vm_area_struct *vma,
		unsigned long start, unsigned long end)
{
	if (vma->vm_flags & (1UL << 39))
		vma_adjust_dmabuf_huge(vma, start, end, 0);
	else
		vma_adjust_trans_huge(vma, start, end, 0);
}
