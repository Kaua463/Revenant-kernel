/* SPDX-License-Identifier: GPL-2.0-only */
/* NEW audit-producer preflight, NOT recovered Xiaomi code or a shipping hook.
 * For a disposable ARM64/4K/VA39 runtime test only. The caller must additionally
 * hold mmap_write_lock, walk the real destination tables to establish emptiness,
 * own the backing allocation until all VMA file refs disappear, and let mmap's
 * failure path unmap any partially published mappings before backing release.
 * Scalar validation below does NOT establish any of those lifetime/lock facts.
 */
#ifndef RECOVERED_DMA_AUDIT_MAP_CONTRACT_H
#define RECOVERED_DMA_AUDIT_MAP_CONTRACT_H

#define DMA_AUDIT_BLOCK_BYTES (1ULL << 21)
#define DMA_AUDIT_ADDRESS_LIMIT (1ULL << 39)

enum dma_audit_map_reason {
	DMA_AUDIT_MAP_OK = 0,
	DMA_AUDIT_BAD_VA_RANGE,
	DMA_AUDIT_BAD_ALIGNMENT,
	DMA_AUDIT_BAD_BACKING_RANGE,
	DMA_AUDIT_BACKING_OVERRUN,
	DMA_AUDIT_PRIVATE_MAPPING,
	DMA_AUDIT_DEST_NOT_EMPTY,
};

static inline enum dma_audit_map_reason dma_audit_map_check(
		unsigned long long start, unsigned long long end,
		unsigned long long backing_phys, unsigned long long backing_bytes,
		unsigned long long offset_bytes, int shared, int destination_empty)
{
	unsigned long long length;

	if (end <= start || end > DMA_AUDIT_ADDRESS_LIMIT)
		return DMA_AUDIT_BAD_VA_RANGE;
	if ((start | end | backing_phys | offset_bytes) & (DMA_AUDIT_BLOCK_BYTES - 1))
		return DMA_AUDIT_BAD_ALIGNMENT;
	if (!backing_bytes || backing_bytes & (DMA_AUDIT_BLOCK_BYTES - 1) ||
	    backing_phys >= DMA_AUDIT_ADDRESS_LIMIT ||
	    backing_bytes > DMA_AUDIT_ADDRESS_LIMIT - backing_phys)
		return DMA_AUDIT_BAD_BACKING_RANGE;
	length = end - start;
	/* Subtract only after proving offset in range; no wrapped offset+length. */
	if (offset_bytes > backing_bytes || length > backing_bytes - offset_bytes)
		return DMA_AUDIT_BACKING_OVERRUN;
	if (!shared)
		return DMA_AUDIT_PRIVATE_MAPPING;
	if (!destination_empty)
		return DMA_AUDIT_DEST_NOT_EMPTY;
	return DMA_AUDIT_MAP_OK;
}
#endif
