/* SPDX-License-Identifier: GPL-2.0-only */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include "audit-data.h"

int main(void)
{
	const size_t bytes = 4 * 1024 * 1024;
	const uint64_t seed = UINT64_C(0x8400);
	uint64_t *data = malloc(bytes);
	assert(data);
	audit_fill(data, bytes, seed);
	assert(audit_mismatch(data, 0, bytes, seed) == SIZE_MAX);
	for (size_t offset = 0; offset < bytes; offset += 4096) {
		data[offset / 8] ^= 1;
		assert(audit_mismatch(data, 0, bytes, seed) == offset);
		assert(audit_mismatch(data, offset + 4096, bytes, seed) == SIZE_MAX);
		data[offset / 8] ^= 1;
	}
	assert(audit_mismatch(data, 4096, bytes - 4096, seed) == SIZE_MAX);
	assert(audit_mismatch(data, bytes, bytes, seed) == SIZE_MAX);
	free(data);
	puts("PASS: data oracle detects 1024 page corruptions; not kernel/runtime proof");
	return 0;
}
