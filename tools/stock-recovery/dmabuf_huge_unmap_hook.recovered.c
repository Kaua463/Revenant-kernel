/* Review-only zap_pmd_range hook. Call instead of the generic huge-PMD
 * branch when VMA bit 39 is set. true skips PTE removal; false falls through
 * to the existing pmd_none/zap_pte_range path. Not installed/exported.
 */
static bool dmabuf_huge_unmap_prepare(struct mmu_gather *tlb,
		struct vm_area_struct *vma, pmd_t *pmd,
		unsigned long addr, unsigned long next)
{
	if (pmd_trans_huge(*pmd)) {
		if (next - addr == HPAGE_PMD_SIZE)
			return zap_dmabuf_huge_pmd(tlb, vma, pmd, addr) != 0;
		zap_split_dmabuf_huge_pmd(vma, pmd, addr, false, NULL);
	}
	return false;
}
