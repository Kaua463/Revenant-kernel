/* Pinned stock lock/zap semantics, NOT installed.
 * Requires split PMD ptlocks (pmd_ptdesc/ptlock_ptr match this ARM64 stock).
 * Deposited PTE-table release is not DMA-BUF backing-page release.
 */
spinlock_t *__pmd_dmabuf_huge_lock(pmd_t *pmd, struct vm_area_struct *vma)
{
	spinlock_t *ptl = ptlock_ptr(pmd_ptdesc(pmd));

	(void)vma;
	spin_lock(ptl);
	if (!pmd_trans_huge(*pmd)) {
		spin_unlock(ptl);
		return NULL;
	}
	return ptl;
}

int zap_dmabuf_huge_pmd(struct mmu_gather *tlb, struct vm_area_struct *vma,
		pmd_t *pmd, unsigned long address)
{
	spinlock_t *ptl = __pmd_dmabuf_huge_lock(pmd, vma);
	pgtable_t pgtable;

	if (!ptl)
		return 0;
	pmdp_huge_get_and_clear(tlb->mm, address, pmd);
	tlb_remove_pmd_tlb_entry(tlb, pmd, address);
	pgtable = pgtable_trans_huge_withdraw(tlb->mm, pmd);
	pte_free(tlb->mm, pgtable);
	mm_dec_nr_ptes(tlb->mm);
	spin_unlock(ptl);
	atomic64_inc(&dmabuf_hugetlb_pmd_zap);
	return 1;
}
