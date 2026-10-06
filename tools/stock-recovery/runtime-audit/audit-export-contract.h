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
#endif
