/* SPDX-License-Identifier: GPL-2.0-only */
/* New disposable-test selector. NOT Xiaomi code or an allocation model. */
#ifndef DMA_AUDIT_FAULT_PLAN_H
#define DMA_AUDIT_FAULT_PLAN_H

struct dma_audit_fault_plan {
	unsigned long owner;
	unsigned long mm;
	unsigned int ordinal;
	unsigned int seen;
	unsigned int fired;
};

/* Caller must serialize arm/check/reset. Tokens are compared, never read. */
static inline int dma_audit_fault_arm(struct dma_audit_fault_plan *plan,
		unsigned long owner, unsigned long mm, unsigned int ordinal)
{
	*plan = (struct dma_audit_fault_plan){0};
	if (!owner || !mm || ordinal < 1 || ordinal > 2)
		return 0;
	plan->owner = owner;
	plan->mm = mm;
	plan->ordinal = ordinal;
	return 1;
}

static inline int dma_audit_fault_check(struct dma_audit_fault_plan *plan,
		unsigned long owner, unsigned long mm)
{
	if (!plan->ordinal || plan->fired || plan->owner != owner || plan->mm != mm)
		return 0;
	plan->seen++;
	if (plan->seen != plan->ordinal)
		return 0;
	plan->fired = 1;
	return 1;
}

#endif
