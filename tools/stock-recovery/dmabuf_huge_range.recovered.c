/* Pinned stock: ARM64 4K/39-bit VA, three page-table levels. NOT installed.
 * VMA bit 39 is proven as a guard, but its original macro name/producer
 * remains unverified. Do not assign anonymous-THP semantics to this flag.
 * Caller must supply a nonempty valid VMA range and stable page tables.
 */
#define DMABUF_RECOVERED_VMA_BIT_39 (1UL << 39)

void __split_dmabuf_huge_range(struct vm_area_struct *vma)
{
	unsigned long address = vma->vm_start, end = vma->vm_end;
	pgd_t *pgd = pgd_offset(vma->vm_mm, address);

	do {
		unsigned long next = pgd_addr_end(address, end);

		if ((pgd_val(*pgd) & 3) == 3) {
			pmd_t *pmd;

			BUG_ON(!(vma->vm_flags & DMABUF_RECOVERED_VMA_BIT_39));
			/* Exact stock descriptor PA mask, not generic PHYS_MASK. */
			pmd = (pmd_t *)__va(pgd_val(*pgd) & 0x7ffffff000UL);
			pmd += (address >> 21) & 511;
			do {
				unsigned long pmd_next = pmd_addr_end(address, next);

				if (pmd_trans_huge(*pmd))
					__split_dmabuf_huge_pmd(vma, pmd, address,
						false, NULL);
				pmd++;
				address = pmd_next;
			} while (address != next);
		}
		pgd++;
		address = next;
	} while (address != end);
}

void split_dmabuf_huge_range(struct vm_area_struct *vma)
{
	__split_dmabuf_huge_range(vma);
}
