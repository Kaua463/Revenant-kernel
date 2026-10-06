/* Pinned ARM64 4K/VA39 remap reconstruction. NOT installed.
 * map_type==0: deposited-table PMD path; every other value: PTE path.
 * Failed allocation returns -ENOMEM without undoing prior successful maps.
 * Alignment/ownership/caller unwind remain mandatory integration gates.
 */
int dmabuf_huge_remap_pfn_range(struct vm_area_struct *vma,
		unsigned long address, unsigned long pfn, unsigned long size,
		pgprot_t prot, unsigned int map_type)
{
	struct mm_struct *mm = vma->vm_mm;
	unsigned long end = address + PAGE_ALIGN(size);
	unsigned long physical_offset;
	pgd_t *pgd;

	BUG_ON(address & ~PAGE_MASK);
	if (is_cow_mapping(vma->vm_flags)) {
		if (address != vma->vm_start || end != vma->vm_end)
			return -EINVAL;
		vma->vm_pgoff = pfn;
	}
	vm_flags_set(vma, VM_IO | VM_PFNMAP | VM_DONTEXPAND | VM_DONTDUMP);
	if (!map_type)
		vm_flags_set(vma, 1UL << 39);
	BUG_ON(address >= end);
	physical_offset = (pfn - (address >> PAGE_SHIFT)) << PAGE_SHIFT;
	pgd = pgd_offset(mm, address);
	do {
		unsigned long next = pgd_addr_end(address, end);
		pmd_t *pmd;

		if (!pgd)
			return -ENOMEM;
		/* pud folds into pgd in this exact three-level stock. */
		if (pgd_none(*pgd) && __pmd_alloc(mm, (pud_t *)pgd, address))
			return -ENOMEM;
		pmd = (pmd_t *)__va(pgd_val(*pgd) & 0x7ffffff000UL);
		pmd += (address >> 21) & 511;
		if (!pmd)
			return -ENOMEM;
		do {
			unsigned long pmd_next = pmd_addr_end(address, next);
			spinlock_t *ptl;

			if (!map_type) {
				pgtable_t pgtable = pte_alloc_one(mm);

				if (!pgtable)
					return -ENOMEM;
				ptl = pmd_lock(mm, pmd);
				pgtable_trans_huge_deposit(mm, pmd, pgtable);
				mm_inc_nr_ptes(mm);
				/* Stock ignores pmd_set_huge return. No added alignment
				 * guarantee: caller must prove 2MiB suitability.
				 */
				pmd_set_huge(pmd, (address + physical_offset) & PAGE_MASK,
						prot);
				spin_unlock(ptl);
				atomic64_inc(&dmabuf_hugetlb_pmd_map);
			} else {
				pte_t *pte = pte_alloc_map_lock(mm, pmd, address, &ptl);
				unsigned int count = (pmd_next - address) >> PAGE_SHIFT;
				unsigned long value;

				if (!pte)
					return -ENOMEM;
				BUG_ON(!pte_none(*pte));
				value = (pgprot_val(prot) & 0xfeefffffffffffffUL) |
					((address + physical_offset) & 0xfeeffffffffff000UL);
				set_ptes(mm, address, pte, __pte(value | (1UL << 56)), count);
				atomic64_inc(&dmabuf_hugetlb_contpte_map);
				pte_unmap_unlock(pte, ptl);
			}
			pmd++;
			address = pmd_next;
		} while (address != next);
		pgd++;
		address = next;
	} while (address != end);
	return 0;
}
