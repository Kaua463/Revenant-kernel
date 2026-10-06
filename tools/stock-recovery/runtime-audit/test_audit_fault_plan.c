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
	for (unsigned int site = DMA_AUDIT_FAULT_PMD_TABLE; site <= DMA_AUDIT_FAULT_LEAF; site++) {
		for (target = 1; target <= 2; target++) {
			assert(dma_audit_fault_arm_site(&plan, 11, 22, site, target));
			for (call = 1; call <= 8; call++) {
				unsigned int seen = plan.seen;
				assert(!dma_audit_fault_check_site(&plan, 11, 22, site ^ 1));
				assert(!dma_audit_fault_check_site(&plan, 11, 22, 2));
				assert(!dma_audit_fault_check_site(&plan, 33, 22, site));
				assert(!dma_audit_fault_check_site(&plan, 11, 44, site));
				assert(plan.seen == seen);
				assert(dma_audit_fault_check_site(&plan, 11, 22, site) == (call == target));
			}
			assert(plan.seen == target && plan.fired == 1);
		}
	}
	assert(!dma_audit_fault_arm_site(&plan, 11, 22, 2, 1));
	assert(!plan.ordinal && !plan.seen && !plan.fired);
	assert(dma_audit_fault_arm_site(&plan, 11, 22, DMA_AUDIT_FAULT_PMD_TABLE, 1));
	/* Legacy LEAF check must neither fire nor consume a PMD-table fault. */
	assert(!dma_audit_fault_check(&plan, 11, 22));
	assert(plan.seen == 0 && plan.fired == 0);
	assert(dma_audit_fault_check_site(&plan, 11, 22, DMA_AUDIT_FAULT_PMD_TABLE));
	return 0;
}
