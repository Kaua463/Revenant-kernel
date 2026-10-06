/* Pinned DyperOS 3.0.304 ARM64 split-body reconstruction; NOT installed.
 * PMD-to-PTE writes and helper/barrier ordering have exact-stock differential
 * tests with modeled helpers. MMU notifier/TLB/lifetime/concurrency remain
 * separate gates; no claim that a source tree can already ship this function.
 * No anonymous-THP refcount/rmap operations are assumed for DMA-BUF mappings.
 */
void __split_dmabuf_huge_pmd(struct vm_area_struct *vma, pmd_t *pmd,
		unsigned long address, bool freeze, struct folio *folio)
{
	struct mmu_notifier_range range;
	struct mm_struct *mm = vma->vm_mm;
	spinlock_t *ptl;
	pgtable_t pgtable;
	pmd_t old, table;
	pte_t *pte, entry;
	unsigned long offset, physical;
	bool dirty;

	(void)freeze;
	address &= HPAGE_PMD_MASK;
	mmu_notifier_range_init_owner(&range, MMU_NOTIFY_CLEAR, 0, mm,
		address, address + HPAGE_PMD_SIZE, NULL);
	mmu_notifier_invalidate_range_start(&range);
	ptl = pmd_lock(mm, pmd);
	if (!pmd_trans_huge(*pmd))
		goto out;
	if (folio && page_folio(pmd_page(*pmd)) != folio)
		goto out;
	pgtable = pgtable_trans_huge_withdraw(mm, pmd);
	old = pmdp_invalidate(vma, address, pmd);
	dirty = pmd_dirty(old);
	pmd_populate(mm, &table, pgtable);
	physical = pmd_val(old) & 0xffffffe00000UL;
	for (offset = 0; offset < HPAGE_PMD_SIZE; offset += PAGE_SIZE) {
		entry = __pte(pgprot_val(vma->vm_page_prot) | (physical + offset));
		if (pmd_write(old))
			entry = pte_mkwrite_novma(entry);
		if (!pmd_young(old))
			entry = pte_mkold(entry);
		if (dirty)
			entry = pte_mkdirty(entry);
		pte = pte_offset_kernel(&table, address + offset);
		BUG_ON(!pte_none(*pte));
		set_pte_at(mm, address + offset, pte, pte_mkspecial(entry));
	}
	smp_wmb();
	pmd_populate(mm, pmd, pgtable);
	atomic64_inc(&dmabuf_hugetlb_pmd_split);
out:
	spin_unlock(ptl);
	mmu_notifier_invalidate_range_end(&range);
}
