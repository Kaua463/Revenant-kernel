/* Review-only move_page_tables hook for VMA bit 39. true consumes extent;
 * false resumes existing PTE path. No destination/extent validation here:
 * those belong to the caller and move helper. Not installed/exported.
 */
static bool dmabuf_huge_move_prepare(struct vm_area_struct *vma,
		unsigned long old_addr, unsigned long new_addr,
		pmd_t *old_pmd, pmd_t *new_pmd, unsigned long extent,
		bool need_rmap_locks)
{
	if (pmd_trans_huge(*old_pmd)) {
		if (extent == HPAGE_PMD_SIZE &&
			move_dmabuf_huge_pmd(vma, old_addr, new_addr,
				old_pmd, new_pmd, need_rmap_locks))
			return true;
		__split_dmabuf_huge_pmd(vma, old_pmd, old_addr, false, NULL);
	}
	return false;
}
