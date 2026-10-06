/* SPDX-License-Identifier: GPL-2.0-only */
#include <assert.h>
#include "audit-fault-plan.h"

int main(void)
{
	struct dma_audit_fault_plan plan;
	unsigned int target, call;
	for (target = 1; target <= 2; target++) {
		assert(dma_audit_fault_arm(&plan, 11, 22, target));
		for (call = 1; call <= 8; call++) {
			unsigned int seen = plan.seen;
			/* Same mm in another task, or same task/wrong mm: no effect. */
			assert(!dma_audit_fault_check(&plan, 33, 22));
			assert(!dma_audit_fault_check(&plan, 11, 44));
			assert(!dma_audit_fault_check(&plan, 0, 0));
			assert(plan.seen == seen);
			assert(dma_audit_fault_check(&plan, 11, 22) == (call == target));
		}
		assert(plan.seen == target && plan.fired == 1);
	}
	for (target = 0; target <= 4; target++) {
		if (target == 1 || target == 2)
			continue;
		assert(!dma_audit_fault_arm(&plan, 11, 22, target));
		assert(!dma_audit_fault_check(&plan, 11, 22));
		assert(!plan.ordinal && !plan.seen && !plan.fired);
	}
	assert(!dma_audit_fault_arm(&plan, 0, 22, 1));
	assert(!dma_audit_fault_arm(&plan, 11, 0, 1));
	assert(!dma_audit_fault_check(&plan, 11, 22));
	/* Explicit re-arm resets the previous fired/call state. */
	assert(dma_audit_fault_arm(&plan, 11, 22, 2));
	assert(!dma_audit_fault_check(&plan, 11, 22));
	assert(dma_audit_fault_arm(&plan, 11, 22, 1));
	assert(dma_audit_fault_check(&plan, 11, 22));
	return 0;
}
