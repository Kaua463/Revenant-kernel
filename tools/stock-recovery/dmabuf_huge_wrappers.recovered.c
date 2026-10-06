/* Hash-pinned stock wrapper semantics; not installed.
 * Page-table split, MMU/TLB and lifetime implementations remain unrecovered.
 * freeze is deliberately ignored by stock wrappers: no inferred THP semantics.
 */
void zap_split_dmabuf_huge_pmd(struct vm_area_struct *vma, pmd_t *pmd,
		unsigned long address, bool freeze, struct folio *folio)
{
	(void)freeze;
	__split_dmabuf_huge_pmd(vma, pmd, address, false, folio);
}

void split_dmabuf_huge_pmd_address(struct vm_area_struct *vma,
		unsigned long address, bool freeze, struct folio *folio)
{
	pmd_t *pmd;

	(void)freeze;
	pmd = mm_find_pmd(vma->vm_mm, address);
	if (pmd)
		__split_dmabuf_huge_pmd(vma, pmd, address, false, folio);
}

static void dmabuf_recovered_split_boundary(struct vm_area_struct *vma,
		unsigned long address)
{
	pmd_t *pmd;

	if ((address & (HPAGE_PMD_SIZE - 1)) && vma &&
	    vma->vm_start <= (address & HPAGE_PMD_MASK) &&
	    ((address + HPAGE_PMD_SIZE - 1) & HPAGE_PMD_MASK) <= vma->vm_end) {
		pmd = mm_find_pmd(vma->vm_mm, address);
		if (pmd)
			__split_dmabuf_huge_pmd(vma, pmd, address, false, NULL);
	}
}

void vma_adjust_dmabuf_huge(struct vm_area_struct *vma, unsigned long start,
		unsigned long end, long adj_next)
{
	struct vm_area_struct *next;
	unsigned long next_start;

	dmabuf_recovered_split_boundary(vma, start);
	dmabuf_recovered_split_boundary(vma, end);
	if (adj_next > 0) {
		next = find_vma(vma->vm_mm, vma->vm_end);
		/* Stock dereferences next before its later NULL test. Caller lifetime
		 * and find_vma success must be established before integration.
		 */
		next_start = next->vm_start + adj_next;
		dmabuf_recovered_split_boundary(next, next_start);
	}
}
