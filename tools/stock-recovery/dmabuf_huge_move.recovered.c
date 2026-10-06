/* Stock move reconstruction, NOT installed. ARM64 split PMD ptlocks.
 * Stronger destination BUG than generic move_huge_pmd; no soft-dirty edit.
 * Caller lock ordering/lifetime, architecture alternatives and flush behavior
 * need differential/integration validation before any runtime use.
 */
bool move_dmabuf_huge_pmd(struct vm_area_struct *vma,
		unsigned long old_address, unsigned long new_address,
		pmd_t *old_pmd, pmd_t *new_pmd, bool need_rmap_locks)
{
	struct mm_struct *mm;
	spinlock_t *old_ptl, *new_ptl;
	bool moved = false, different_page;
	pmd_t entry;

	if (need_rmap_locks) {
		if (vma->vm_file)
			i_mmap_lock_write(vma->vm_file->f_mapping);
		if (vma->anon_vma)
			anon_vma_lock_write(vma->anon_vma);
	}
	BUG_ON(!pmd_none(*new_pmd));
	mm = vma->vm_mm;
	old_ptl = __pmd_dmabuf_huge_lock(old_pmd, vma);
	if (!old_ptl)
		goto out_rmap;
	new_ptl = ptlock_ptr(pmd_ptdesc(new_pmd));
	different_page = pmd_ptdesc(old_pmd) != pmd_ptdesc(new_pmd);
	if (different_page)
		spin_lock(new_ptl);
	entry = pmdp_huge_get_and_clear(mm, old_address, old_pmd);
	if (different_page) {
		pgtable_t table = pgtable_trans_huge_withdraw(mm, old_pmd);

		pgtable_trans_huge_deposit(mm, new_pmd, table);
	}
	set_pmd_at(mm, new_address, new_pmd, entry);
	if (pmd_present(entry))
		flush_tlb_range(vma, old_address, old_address + HPAGE_PMD_SIZE);
	if (different_page)
		spin_unlock(new_ptl);
	spin_unlock(old_ptl);
	moved = true;
out_rmap:
	if (need_rmap_locks) {
		if (vma->anon_vma)
			anon_vma_unlock_write(vma->anon_vma);
		if (vma->vm_file)
			i_mmap_unlock_write(vma->vm_file->f_mapping);
	}
	return moved;
}
