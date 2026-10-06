/* SPDX-License-Identifier: GPL-2.0-only */
/* Host scalar gate tests only. Not MMU/producer ownership validation. */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include "audit-map-contract.h"

static int reference(uint64_t start, uint64_t end, uint64_t phys,
		uint64_t bytes, uint64_t offset, int shared, int empty)
{
	const uint64_t block = UINT64_C(2097152), limit = UINT64_C(549755813888);
	if (start >= end || end > limit || start % block || end % block ||
	    phys % block || offset % block || bytes == 0 || bytes % block ||
	    phys >= limit || bytes > limit || phys > limit - bytes || offset > bytes)
		return 0;
	return end - start <= bytes - offset && shared && empty;
}

int main(void)
{
	const uint64_t block = DMA_AUDIT_BLOCK_BYTES, limit = DMA_AUDIT_ADDRESS_LIMIT;
	const uint64_t starts[] = {0, 1, block, 3*block, limit-block, limit, UINT64_MAX};
	const uint64_t lengths[] = {0, 1, block, 2*block, 4*block};
	const uint64_t physical[] = {0, 1, UINT64_C(0x40000000), limit-block, limit, UINT64_MAX};
	const uint64_t sizes[] = {0, 1, block, 2*block, 4*block, UINT64_MAX};
	const uint64_t offsets[] = {0, 1, block, 2*block, 4*block, UINT64_MAX};
	unsigned cases = 0, accepted = 0;
	_Static_assert(sizeof(unsigned long long) == 8, "audit requires 64-bit scalars");
	assert(dma_audit_map_check(block, 2*block, 0x40000000, 2*block, 0, 1, 1) == DMA_AUDIT_MAP_OK);
	assert(dma_audit_map_check(0, 0, 0, block, 0, 1, 1) == DMA_AUDIT_BAD_VA_RANGE);
	assert(dma_audit_map_check(1, block, 0, block, 0, 1, 1) == DMA_AUDIT_BAD_ALIGNMENT);
	assert(dma_audit_map_check(0, block, 0, 0, 0, 1, 1) == DMA_AUDIT_BAD_BACKING_RANGE);
	assert(dma_audit_map_check(0, 2*block, 0, block, 0, 1, 1) == DMA_AUDIT_BACKING_OVERRUN);
	assert(dma_audit_map_check(0, block, 0, block, 0, 0, 1) == DMA_AUDIT_PRIVATE_MAPPING);
	assert(dma_audit_map_check(0, block, 0, block, 0, 1, 0) == DMA_AUDIT_DEST_NOT_EMPTY);
	for (unsigned a = 0; a < sizeof(starts)/sizeof(*starts); a++)
	 for (unsigned b = 0; b < sizeof(lengths)/sizeof(*lengths); b++)
	  for (unsigned c = 0; c < sizeof(physical)/sizeof(*physical); c++)
	   for (unsigned d = 0; d < sizeof(sizes)/sizeof(*sizes); d++)
	    for (unsigned e = 0; e < sizeof(offsets)/sizeof(*offsets); e++)
	     for (int shared = 0; shared < 2; shared++)
	      for (int empty = 0; empty < 2; empty++) {
		uint64_t end = starts[a] + lengths[b]; /* explicit defined u64 wrap */
		int actual = dma_audit_map_check(starts[a], end, physical[c], sizes[d], offsets[e], shared, empty) == DMA_AUDIT_MAP_OK;
		assert(actual == reference(starts[a], end, physical[c], sizes[d], offsets[e], shared, empty));
		accepted += actual; cases++;
	      }
	assert(accepted > 0 && accepted < cases);
	printf("PASS: %u scalar producer preflights (%u accepted); no lock/ownership/MMU proof\n", cases, accepted);
	return 0;
}
