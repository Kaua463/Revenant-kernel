/* SPDX-License-Identifier: GPL-2.0-only */
/* Fixed RAM-only VM factory commands. No pointers, PFNs or user structures. */
#ifndef DMA_AUDIT_EXPORT_CONTRACT_H
#define DMA_AUDIT_EXPORT_CONTRACT_H
#ifdef __KERNEL__
#include <linux/ioctl.h>
#else
#include <sys/ioctl.h>
#endif
#define DMA_AUDIT_EXPORT_PMD _IO('D', 0x40)
#define DMA_AUDIT_EXPORT_PTE _IO('D', 0x41)
#define DMA_AUDIT_EXPORT_LIVE _IO('D', 0x42)
/* Disposable per-call injection: 4 ownership acquisition edges per mode. */
#define DMA_AUDIT_EXPORT_TABLE_BYTES _IO('D', 0x44)
#define DMA_AUDIT_EXPORT_FAIL(mode, stage) _IO('D', 0x50 + (mode) * 4 + (stage))
/* Owner-scoped VMA duplication edges: split, copy, fork; ordinals 1/2. */
#define DMA_AUDIT_VMA_ARM(site, ordinal) _IO('D', 0x60 + (site) * 2 + (ordinal) - 1)
#define DMA_AUDIT_VMA_FIRED _IO('D', 0x66)
#define DMA_AUDIT_VMA_DISARM _IO('D', 0x67)
#endif
