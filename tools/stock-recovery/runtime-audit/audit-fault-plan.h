/* SPDX-License-Identifier: GPL-2.0-only */
/* New disposable-test selector. NOT Xiaomi code or an allocation model. */
#ifndef DMA_AUDIT_FAULT_PLAN_H
#define DMA_AUDIT_FAULT_PLAN_H

enum dma_audit_fault_site {
	DMA_AUDIT_FAULT_PMD_TABLE = 0,
	DMA_AUDIT_FAULT_LEAF = 1,
};

struct dma_audit_fault_plan {
	unsigned long owner;
	unsigned long mm;
	unsigned int ordinal;
	unsigned int seen;
	unsigned int fired;
	unsigned int site;
};

/* Caller must serialize arm/check/reset. Tokens are compared, never read. */
static inline int dma_audit_fault_arm_site(struct dma_audit_fault_plan *plan,
		unsigned long owner, unsigned long mm, unsigned int site,
		unsigned int ordinal)
{
	*plan = (struct dma_audit_fault_plan){0};
	if (!owner || !mm || ordinal < 1 || ordinal > 2 || site > DMA_AUDIT_FAULT_LEAF)
		return 0;
	plan->owner = owner;
	plan->mm = mm;
	plan->ordinal = ordinal;
	plan->site = site;
	return 1;
}

static inline int dma_audit_fault_check_site(struct dma_audit_fault_plan *plan,
		unsigned long owner, unsigned long mm, unsigned int site)
{
	if (!plan->ordinal || plan->fired || plan->owner != owner || plan->mm != mm ||
	    plan->site != site)
		return 0;
	plan->seen++;
	if (plan->seen != plan->ordinal)
		return 0;
	plan->fired = 1;
	return 1;
}

/* Existing partial-leaf workload retains its exact one-shot behavior. */
static inline int dma_audit_fault_arm(struct dma_audit_fault_plan *plan,
		unsigned long owner, unsigned long mm, unsigned int ordinal)
{
	return dma_audit_fault_arm_site(plan, owner, mm, DMA_AUDIT_FAULT_LEAF, ordinal);
}

static inline int dma_audit_fault_check(struct dma_audit_fault_plan *plan,
		unsigned long owner, unsigned long mm)
{
	return dma_audit_fault_check_site(plan, owner, mm, DMA_AUDIT_FAULT_LEAF);
}

#endif
