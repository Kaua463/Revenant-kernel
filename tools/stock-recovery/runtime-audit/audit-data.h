/* SPDX-License-Identifier: GPL-2.0-only */
/* New guest data oracle; not recovered kernel code. */
#ifndef DMA_AUDIT_DATA_H
#define DMA_AUDIT_DATA_H
#include <stddef.h>
#include <stdint.h>

static inline uint64_t audit_word(size_t index, uint64_t seed)
{
	return (UINT64_C(0x9e3779b97f4a7c15) * (uint64_t)(index + 1)) ^ seed;
}

static inline void audit_fill(uint64_t *data, size_t bytes, uint64_t seed)
{
	for (size_t i = 0; i < bytes / sizeof(*data); ++i)
		data[i] = audit_word(i, seed);
}

/* Return byte offset of first mismatch; SIZE_MAX on complete match.
 * start/end are relative to the original full buffer, including after holes.
 */
static inline size_t audit_mismatch(const volatile uint64_t *data,
		size_t start, size_t end, uint64_t seed)
{
	for (size_t i = start / sizeof(*data); i < end / sizeof(*data); ++i)
		if (data[i] != audit_word(i, seed))
			return i * sizeof(*data);
	return SIZE_MAX;
}
#endif
