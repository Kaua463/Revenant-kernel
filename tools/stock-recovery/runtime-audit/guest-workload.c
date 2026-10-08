// SPDX-License-Identifier: GPL-2.0-only
/* New Linux ARM64 QEMU workload. No phone invocation, arbitrary PFN or files. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <unistd.h>
#include "audit-data.h"
#include "audit-export-contract.h"

#define BLOCK (2UL * 1024 * 1024)
#define BYTES (2 * BLOCK)
#define SEED UINT64_C(0x8400)

static void fail(const char *label)
{
	fprintf(stderr, "DMA_GUEST_FAIL: %s errno=%d\n", label, errno);
	exit(1);
}

static void verify(const void *mapping, size_t start, size_t end)
{
	size_t mismatch = audit_mismatch(mapping, start, end, SEED);
	if (mismatch != SIZE_MAX) {
		fprintf(stderr, "DMA_GUEST_FAIL: data offset=%zu\n", mismatch);
		exit(1);
	}
}

static void *reservation(size_t length)
{
	void *base = mmap(NULL, length + BLOCK, PROT_NONE,
			 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	uintptr_t aligned;
	size_t prefix, suffix;

	if (base == MAP_FAILED)
		fail("reserve");
	aligned = ((uintptr_t)base + BLOCK - 1) & ~(uintptr_t)(BLOCK - 1);
	prefix = aligned - (uintptr_t)base;
	suffix = BLOCK - prefix;
	if (prefix && munmap(base, prefix))
		fail("reserve prefix");
	if (suffix && munmap((void *)(aligned + length), suffix))
		fail("reserve suffix");
	return (void *)aligned;
}

static void *map_owned(int fd)
{
	void *hole = reservation(BYTES);
	void *mapped = mmap(hole, BYTES, PROT_READ | PROT_WRITE,
			    MAP_SHARED | MAP_FIXED, fd, 0);
	if (mapped != hole)
		fail("map own buffer");
	return mapped;
}

static void reject(int fd, size_t length, int protection, int flags, off_t offset)
{
	void *hole = reservation(BYTES);
	void *result;

	errno = 0;
	result = mmap(hole, length, protection, flags | MAP_FIXED, fd, offset);
	if (result != MAP_FAILED || (errno != EINVAL && errno != EPERM))
		fail("invalid mapping accepted/unexpected errno");
	if (munmap(hole, BYTES))
		fail("reject reservation cleanup");
}

struct reader {
	const void *alias;
	size_t bytes;
	atomic_int stop;
	atomic_ulong passes;
};

static void *read_alias(void *argument)
{
	struct reader *reader = argument;
	while (!atomic_load_explicit(&reader->stop, memory_order_acquire)) {
		verify(reader->alias, 0, reader->bytes);
		atomic_fetch_add_explicit(&reader->passes, 1, memory_order_relaxed);
	}
	return NULL;
}

static void migrate_and_verify(const void *alias);

static void verify_prefork_lifecycle(void **first, const void *alias,
		size_t alias_bytes, const char *label)
{
	struct reader reader = {.alias = alias, .bytes = alias_bytes};
	pthread_t thread;
	void *target, *moved;
	unsigned long baseline;

	atomic_init(&reader.stop, 0);
	atomic_init(&reader.passes, 0);
	if (pthread_create(&thread, NULL, read_alias, &reader))
		fail("pre-fork reader create");
	while (!atomic_load_explicit(&reader.passes, memory_order_relaxed))
		sched_yield();
	/* BEFORE fork clears bit39: exercise the original huge-PMD move first.
	 * Then full and partial protections exercise retained/split mappings.
	 * The separate alias stays readable while the moved VMA is PROT_NONE.
	 */
	target = reservation(BYTES);
	moved = mremap(*first, BYTES, BYTES, MREMAP_MAYMOVE | MREMAP_FIXED, target);
	if (moved != target)
		fail("pre-fork huge mapping move");
	*first = moved;
	verify(moved, 0, BYTES);
	if (mprotect(moved, BYTES, PROT_NONE) ||
	    mprotect(moved, BYTES, PROT_READ | PROT_WRITE) ||
	    mprotect((char *)moved + BLOCK, 4096, PROT_NONE) ||
	    mprotect((char *)moved + BLOCK, 4096, PROT_READ | PROT_WRITE))
		fail("pre-fork full/partial protect restore");
	verify(moved, 0, BYTES);
	verify(alias, 0, alias_bytes);
	/* PFNMAP must reject discard rather than lose non-faultable backing. */
	errno = 0;
	if (!madvise(moved, BYTES, MADV_DONTNEED) || errno != EINVAL)
		fail("pre-fork PFNMAP discard guard");
	verify(moved, 0, BYTES);
	migrate_and_verify(moved);
	baseline = atomic_load_explicit(&reader.passes, memory_order_relaxed);
	while (atomic_load_explicit(&reader.passes, memory_order_relaxed) <= baseline)
		sched_yield();
	atomic_store_explicit(&reader.stop, 1, memory_order_release);
	if (pthread_join(thread, NULL))
		fail("pre-fork reader join");
	printf("DMA_GUEST_PRE_FORK: %s move=1 protect=1 read_concurrent=1 cpu_migrate=1 data_verified=1\n", label);
}

static void *move_split_mapping(void *first, const char *label)
{
	const size_t offsets[] = {0, BLOCK, BLOCK + 4096};
	const size_t lengths[] = {BLOCK, 4096, BLOCK - 4096};
	unsigned char residency[BYTES / 4096];
	void *target = reservation(BYTES);

	/* Partial mprotect split this VM_SPECIAL range into three VMAs.
	 * vma_merge deliberately refuses VM_SPECIAL, even after restoring RW.
	 * mremap must reject spanning these VMAs; do not change kernel semantics
	 * to accommodate an invalid guest request. FIXED first unmaps its owned
	 * destination, so re-reserve that exact hole before moving each VMA.
	 */
	errno = 0;
	if (mremap(first, BYTES, BYTES, MREMAP_MAYMOVE | MREMAP_FIXED, target) != MAP_FAILED || errno != EFAULT)
		fail("split VMA whole move guard");
	verify(first, 0, BYTES);
	errno = 0;
	if (!mincore(target, BYTES, residency) || errno != ENOMEM)
		fail("split move rejected destination unwind");
	if (mmap(target, BYTES, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS |
		 MAP_FIXED_NOREPLACE, -1, 0) != target)
		fail("split move destination reservation");
	for (size_t index = 0; index < 3; ++index) {
		void *destination = (char *)target + offsets[index];
		if (mremap((char *)first + offsets[index], lengths[index], lengths[index],
			   MREMAP_MAYMOVE | MREMAP_FIXED, destination) != destination)
			fail("split VMA segment move");
	}
	verify(target, 0, BYTES);
	printf("DMA_GUEST_SPLIT_MOVE: %s segments=3 whole_move_errno=%d data_verified=1\n", label, EFAULT);
	return target;
}

static void migrate_and_verify(const void *alias)
{
	cpu_set_t original, one;
	unsigned int count = 0;

	if (sched_getaffinity(0, sizeof(original), &original))
		fail("get affinity");
	for (int cpu = 0; cpu < CPU_SETSIZE; ++cpu) {
		if (!CPU_ISSET(cpu, &original))
			continue;
		CPU_ZERO(&one);
		CPU_SET(cpu, &one);
		if (sched_setaffinity(0, sizeof(one), &one))
			fail("set affinity");
		verify(alias, 0, BYTES);
		++count;
	}
	if (count < 2)
		fail("SMP guest requires >=2 available CPUs");
	if (sched_setaffinity(0, sizeof(original), &original))
		fail("restore affinity");
}

static void verify_cross_pgd(int fd, const char *device)
{
	const size_t span = 2UL << 30;
	void *base = (void *)(uintptr_t)(15UL << 30);
	void *hole = (void *)(uintptr_t)((16UL << 30) - BLOCK);
	void *mapping;

	/* Both PGD slots must be free; never clobber an unrelated VMA. No
	 * worker threads exist yet, and the kernel preflight checks real tables.
	 */
	if (mmap(base, span, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS |
		 MAP_FIXED_NOREPLACE, -1, 0) != base || munmap(base, span))
		fail("cross-PGD range reservation");
	mapping = mmap(hole, BYTES, PROT_READ | PROT_WRITE,
		       MAP_SHARED | MAP_FIXED_NOREPLACE, fd, 0);
	if (mapping != hole)
		fail("cross-PGD mapping");
	verify(mapping, 0, BYTES);
	printf("DMA_GUEST_CROSS_PGD: %s bytes=4194304 root_slots=2 data_verified=1\n", device);
	if (munmap(mapping, BYTES))
		fail("cross-PGD mapping teardown");
}

static void exercise(const char *device, int inject)
{
	int fd = open(device, O_RDWR | O_CLOEXEC), status;
	void *first, *alias, *moved;
	pid_t child;
	pthread_t thread;
	struct reader reader;

	if (fd < 0)
		fail("open audit device");
	if (inject) {
		unsigned char residency[BYTES / 4096];
		void *hole = reservation(BYTES);
		void *result;

		if (strstr(device, "-table-")) {
			unsigned int mode = strstr(device, "-pte") != NULL;
			unsigned int cross = strstr(device, "-table-cross-") != NULL;
			const size_t span = (cross ? 2UL : 1UL) << 30;
			void *cold = (void *)(uintptr_t)((cross ? 8UL + 4UL * mode : 4UL + 2UL * mode) << 30);
			/* No MAP_FIXED clobber: fail if any VMA occupies this whole
			 * PGD slot. PROT_NONE does not fault RAM or create PMD tables.
			 * The kernel separately requires the real PUD to be zero.
			 */
			if (munmap(hole, BYTES) ||
			    mmap(cold, span, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS |
				 MAP_FIXED_NOREPLACE, -1, 0) != cold || munmap(cold, span))
				fail("cold PGD-slot reservation");
			hole = cross ? (char *)cold + (1UL << 30) - BLOCK : cold;
			printf("DMA_GUEST_COLD_RANGE mode=%u bytes=%zu aligned=1\n", mode, span);
		}

		errno = 0;
		result = mmap(hole, BYTES, PROT_READ | PROT_WRITE,
			      MAP_SHARED | MAP_FIXED, fd, 0);
		if (result != MAP_FAILED || errno != ENOMEM)
			fail("injected leaf allocation did not return ENOMEM");
		errno = 0;
		if (!mincore(hole, BYTES, residency) || errno != ENOMEM)
			fail("failed mmap left a VMA");
		/* NOREPLACE proves no VMA; producer preflight rejects stale tables.
		 * Reuse the same address, not a fresh one hiding residual mappings.
		 */
		result = mmap(hole, BYTES, PROT_READ | PROT_WRITE,
			      MAP_SHARED | MAP_FIXED_NOREPLACE, fd, 0);
		if (result != hole)
			fail("retry at failed mmap address");
		audit_fill(result, BYTES, SEED);
		verify(result, 0, BYTES);
		if (munmap(result, BYTES))
			fail("retry teardown");
		printf("DMA_GUEST_ENOMEM_PASS: %s same_address_retry=1\n", device);
	}
	reject(fd, 3 * 1024 * 1024, PROT_READ, MAP_SHARED, 0);
	reject(fd, BLOCK, PROT_READ, MAP_PRIVATE, 0);
	reject(fd, BLOCK, PROT_READ | PROT_EXEC, MAP_SHARED, 0);
	reject(fd, BYTES, PROT_READ, MAP_SHARED, BLOCK);
	reject(fd, BLOCK, PROT_READ, MAP_SHARED, BYTES);
	first = map_owned(fd);
	alias = map_owned(fd);
	audit_fill(first, BYTES, SEED);
	verify(alias, 0, BYTES);
	verify_cross_pgd(fd, device);
	if (close(fd))
		fail("close mapped file");
	verify_prefork_lifecycle(&first, alias, BYTES, device);
	/* No descriptor remains: VMA file references must retain backing. */
	child = fork();
	if (child < 0)
		fail("fork");
	if (!child) {
		verify(first, 0, BYTES);
		verify(alias, 0, BYTES);
		if (munmap((char *)first + BLOCK, 4096))
			fail("child partial unmap");
		verify(alias, 0, BYTES);
		((volatile uint64_t *)alias)[0] ^= 5;
		_exit(0);
	}
	if (waitpid(child, &status, 0) != child || !WIFEXITED(status) || WEXITSTATUS(status))
		fail("child result");
	if (((volatile uint64_t *)first)[0] != (audit_word(0, SEED) ^ 5))
		fail("shared fork write visibility");
	((volatile uint64_t *)first)[0] ^= 5;
	verify(first, 0, BYTES);
	printf("DMA_GUEST_FORK_PASS: %s shared_write=1 data_verified=1\n", device);
	reader.alias = alias;
	reader.bytes = BYTES;
	atomic_init(&reader.stop, 0);
	atomic_init(&reader.passes, 0);
	if (pthread_create(&thread, NULL, read_alias, &reader))
		fail("reader create");
	moved = move_split_mapping(first, device);
	verify(moved, 0, BYTES);
	migrate_and_verify(alias);
	if (mprotect((char *)moved + BLOCK, 4096, PROT_NONE) ||
	    mprotect((char *)moved + BLOCK, 4096, PROT_READ | PROT_WRITE))
		fail("protect split/restore");
	verify(moved, 0, BYTES);
	errno = 0;
	if (!mprotect(moved, BYTES, PROT_READ | PROT_EXEC) || errno != EACCES)
		fail("MAYEXEC guard");
	if (munmap((char *)moved + BLOCK, 4096))
		fail("parent partial unmap");
	verify(moved, 0, BLOCK);
	verify(moved, BLOCK + 4096, BYTES);
	if (munmap(moved, BYTES))
		fail("moved mapping teardown");
	verify(alias, 0, BYTES);
	/* Reader's alias stays live throughout other-VMA teardown. */
	while (!atomic_load_explicit(&reader.passes, memory_order_relaxed))
		sched_yield();
	atomic_store_explicit(&reader.stop, 1, memory_order_release);
	if (pthread_join(thread, NULL))
		fail("reader join");
	printf("DMA_GUEST_LAST_UNMAP: %s\n", device);
	if (munmap(alias, BYTES))
		fail("last mapping teardown");
	printf("DMA_GUEST_CASE_PASS: %s reader_passes=%lu\n", device,
	       atomic_load_explicit(&reader.passes, memory_order_relaxed));
}

static void exercise_export(unsigned int mode)
{
	const size_t lengths[] = {4096, 65536, BLOCK, BYTES};
	void *mappings[4], *moved;
	int factory, fd, fd_flags, status;
	pid_t child;
	unsigned int attempt;
	char label[32];

	factory = open("/dev/recovered-dma-export-audit", O_RDWR | O_CLOEXEC);
	if (factory < 0 || ioctl(factory, DMA_AUDIT_EXPORT_LIVE, 0) != 0)
		fail("export factory baseline");
	errno = 0;
	if (ioctl(factory, DMA_AUDIT_EXPORT_PMD, 1) != -1 || errno != EINVAL)
		fail("export nonzero argument accepted");
	errno = 0;
	if (ioctl(factory, _IO('D', 0x43), 0) != -1 || errno != EINVAL)
		fail("export unknown command accepted");
	fd = ioctl(factory, mode ? DMA_AUDIT_EXPORT_PTE : DMA_AUDIT_EXPORT_PMD, 0);
	if (fd < 0)
		fail("export fd installation");
	fd_flags = fcntl(fd, F_GETFD);
	if (fd_flags < 0 || !(fd_flags & FD_CLOEXEC) ||
	    ioctl(factory, DMA_AUDIT_EXPORT_LIVE, 0) != 1)
		fail("export fd ownership/CLOEXEC");
	errno = 0;
	if (mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, BYTES) != MAP_FAILED || errno != EINVAL)
		fail("export core extent bound");
	for (size_t index = 0; index < 4; ++index) {
		uintptr_t mask = lengths[index] >= BLOCK ? BLOCK - 1 :
				 lengths[index] >= 65536 ? 65535 : 4095;
		uintptr_t hint = index == 1 ? UINT64_C(0x20001000) :
				 index == 2 ? UINT64_C(0x40001000) : 0;
		mappings[index] = mmap((void *)hint, lengths[index], PROT_READ | PROT_WRITE,
				       MAP_SHARED, fd, 0);
		if (mappings[index] == MAP_FAILED || ((uintptr_t)mappings[index] & mask) ||
		    (hint && (uintptr_t)mappings[index] != ((hint + mask) & ~mask)))
			fail("DMA-BUF selector alignment");
		printf("DMA_EXPORT_ALIGN mode=%u bytes=%zu mask=%lu aligned=1 hint_checked=%u\n",
		       mode, lengths[index], (unsigned long)mask, (unsigned int)!!hint);
	}
	for (size_t index = 0; index < BYTES / sizeof(uint64_t); ++index)
		if (((volatile uint64_t *)mappings[3])[index])
			fail("export RAM not zeroed");
	audit_fill(mappings[3], BYTES, SEED);
	for (size_t index = 0; index < 4; ++index)
		verify(mappings[index], 0, lengths[index]);
	if (close(fd) || ioctl(factory, DMA_AUDIT_EXPORT_LIVE, 0) != 1)
		fail("DMA-BUF backing lost after close fd");
	if (snprintf(label, sizeof(label), "export-mode-%u", mode) < 0)
		fail("export label");
	verify_prefork_lifecycle(&mappings[3], mappings[2], BLOCK, label);
	errno = 0;
	if (!mprotect(mappings[3], BYTES, PROT_READ | PROT_EXEC) || errno != EACCES)
		fail("export MAYEXEC guard");
	child = fork();
	if (child < 0)
		fail("export fork");
	if (!child) {
		verify(mappings[3], 0, BYTES);
		if (munmap((char *)mappings[3] + BLOCK, 4096))
			fail("export child partial unmap");
		((volatile uint64_t *)mappings[2])[0] ^= 9;
		_exit(0);
	}
	if (waitpid(child, &status, 0) != child || !WIFEXITED(status) || WEXITSTATUS(status))
		fail("export child result");
	if (((volatile uint64_t *)mappings[3])[0] != (audit_word(0, SEED) ^ 9))
		fail("export fork shared write");
	((volatile uint64_t *)mappings[3])[0] ^= 9;
	verify(mappings[3], 0, BYTES);
	printf("DMA_EXPORT_FORK_PASS mode=%u shared_write=1 data_verified=1\n", mode);
	moved = move_split_mapping(mappings[3], label);
	migrate_and_verify(moved);
	for (size_t index = 0; index < 3; ++index) {
		verify(mappings[index], 0, lengths[index]);
		if (munmap(mappings[index], lengths[index]))
			fail("export alias teardown");
	}
	if (ioctl(factory, DMA_AUDIT_EXPORT_LIVE, 0) != 1)
		fail("export lifetime before last unmap");
	verify(moved, 0, BYTES);
	printf("DMA_EXPORT_LAST_UNMAP mode=%u\n", mode);
	if (munmap(moved, BYTES))
		fail("export last mapping teardown");
	for (attempt = 0; attempt < 500; ++attempt) {
		int live = ioctl(factory, DMA_AUDIT_EXPORT_LIVE, 0);
		if (live < 0 || live > 1)
			fail("export live counter invalid");
		if (!live)
			break;
		usleep(1000);
	}
	if (attempt == 500 || close(factory))
		fail("export final release timeout");
	printf("DMA_EXPORT_CASE_PASS mode=%u live=0\n", mode);
}

static void wait_export_empty(int factory)
{
	for (unsigned int i = 0; i < 1000; i++) {
		int live = ioctl(factory, DMA_AUDIT_EXPORT_LIVE, 0);
		if (live < 0 || live > 1)
			fail("extended invalid live count");
		if (!live)
			return;
		usleep(1000);
	}
	fail("extended final release timeout");
}

static void exercise_vma_failures(void)
{
	int factory = open("/dev/recovered-dma-export-audit", O_RDWR | O_CLOEXEC);
	if (factory < 0 || ioctl(factory, DMA_AUDIT_EXPORT_LIVE, 0))
		fail("VMA baseline");
	puts("DMA_VMA_BEGIN");
	for (unsigned int mode = 0; mode < 2; mode++) {
		for (unsigned int test = 0; test < 5; test++) {
			unsigned int site = test < 2 ? 0 : test == 2 ? 1 : 2;
			unsigned int ordinal = test == 1 || test == 4 ? 2 : 1;
			long baseline = ioctl(factory, DMA_AUDIT_EXPORT_TABLE_BYTES, 0);
			int fd = ioctl(factory, mode ? DMA_AUDIT_EXPORT_PTE : DMA_AUDIT_EXPORT_PMD, 0);
			uintptr_t base = UINT64_C(0x2000000000) + ((uintptr_t)test << 32);
			void *maps[2], *target = (void *)(base + (UINT64_C(2) << 30));
			pid_t child = -1;
			int status, result;
			if (baseline < 0 || fd < 0)
				fail("VMA buffer allocation");
			for (unsigned int i = 0; i < 2; i++) {
				void *address = (void *)(base + ((uintptr_t)i << 30));
				maps[i] = mmap(address, BYTES, PROT_READ | PROT_WRITE,
					MAP_SHARED | MAP_FIXED_NOREPLACE, fd, 0);
				if (maps[i] != address)
					fail("VMA cold-PGD map");
			}
			audit_fill(maps[0], BYTES, SEED);
			verify(maps[1], 0, BYTES);
			if (ioctl(factory, DMA_AUDIT_VMA_ARM(site, ordinal), 0))
				fail("VMA fault arm");
			errno = 0;
			if (!site) {
				result = mprotect((char *)maps[0] + BLOCK, 4096, PROT_READ);
			} else if (site == 1) {
				result = mremap(maps[0], BYTES, BYTES,
					MREMAP_MAYMOVE | MREMAP_FIXED, target) == MAP_FAILED ? -1 : 0;
			} else {
				child = fork();
				if (!child)
					_exit(61); /* A successful child here is a failed test. */
				result = child < 0 ? -1 : 0;
			}
			if (result != -1 || errno != ENOMEM ||
			    ioctl(factory, DMA_AUDIT_VMA_FIRED, 0) != 1)
				fail("VMA fault did not fire exactly once");
			if (ioctl(factory, DMA_AUDIT_VMA_DISARM, 0))
				fail("VMA fault disarm");
			verify(maps[0], 0, BYTES);
			verify(maps[1], 0, BYTES);
			/* Retry the original operation through the real generic path. */
			if (!site) {
				if (mprotect(maps[0], BYTES, PROT_READ | PROT_WRITE))
					fail("VMA split retry");
			} else if (site == 1) {
				void *moved = mremap(maps[0], BYTES, BYTES,
					MREMAP_MAYMOVE | MREMAP_FIXED, target);
				if (moved != target)
					fail("VMA copy retry");
				maps[0] = moved;
			} else {
				child = fork();
				if (child < 0)
					fail("VMA fork retry");
				if (!child) {
					verify(maps[0], 0, BYTES);
					verify(maps[1], 0, BYTES);
					_exit(0);
				}
				if (waitpid(child, &status, 0) != child ||
				    !WIFEXITED(status) || WEXITSTATUS(status))
					fail("VMA retry child teardown");
			}
			verify(maps[0], 0, BYTES);
			verify(maps[1], 0, BYTES);
			if (close(fd) || munmap(maps[0], BYTES) || munmap(maps[1], BYTES))
				fail("VMA parent teardown");
			wait_export_empty(factory);
			if (ioctl(factory, DMA_AUDIT_EXPORT_TABLE_BYTES, 0) != baseline)
				fail("VMA fault leaked parent page tables");
			printf("DMA_VMA_PASS mode=%u site=%u ordinal=%u errno=12 retry=1 data_verified=1 live=0 tables_restored=1\n",
				mode, site, ordinal);
		}
	}
	if (close(factory))
		fail("VMA factory close");
	puts("DMA_VMA_END cases=10");
}

static void exercise_extended(void)
{
	int factory = open("/dev/recovered-dma-export-audit", O_RDWR | O_CLOEXEC);
	if (factory < 0 || ioctl(factory, DMA_AUDIT_EXPORT_LIVE, 0))
		fail("extended baseline");
	puts("DMA_EXT_BEGIN");
	for (unsigned int mode = 0; mode < 2; mode++) {
		for (unsigned int stage = 1; stage <= 4; stage++) {
			long before = ioctl(factory, DMA_AUDIT_EXPORT_TABLE_BYTES, 0);
			errno = 0;
			if (before < 0 || ioctl(factory, DMA_AUDIT_EXPORT_FAIL(mode, stage), 0) != -1 ||
			    errno != (stage == 4 ? EMFILE : ENOMEM))
				fail("export acquisition failure not exercised");
			wait_export_empty(factory);
			if (ioctl(factory, DMA_AUDIT_EXPORT_TABLE_BYTES, 0) != before)
				fail("export failure leaked page tables");
			printf("DMA_EXT_FAULT_PASS mode=%u stage=%u live=0 tables_restored=1\n", mode, stage);
		}
		for (unsigned int round = 0; round < 8; round++) {
			int fd = ioctl(factory, mode ? DMA_AUDIT_EXPORT_PTE : DMA_AUDIT_EXPORT_PMD, 0);
			int pipes[2][2], ready[2], status;
			pid_t children[2];
			void *maps[2];
			long before = ioctl(factory, DMA_AUDIT_EXPORT_TABLE_BYTES, 0);
			if (fd < 0 || before < 0)
				fail("extended buffer create");
			for (unsigned int i = 0; i < 2; i++) {
				uintptr_t address = UINT64_C(0x100000000) +
					((uintptr_t)(mode * 16 + round * 2 + i) << 30);
				maps[i] = mmap((void *)address, BYTES, PROT_READ | PROT_WRITE,
					MAP_SHARED | MAP_FIXED_NOREPLACE, fd, 0);
				if (maps[i] != (void *)address || pipe(pipes[i]))
					fail("extended cold-PGD mapping or pipe");
			}
			audit_fill(maps[0], BYTES, SEED);
			verify(maps[1], 0, BYTES);
			for (unsigned int i = 0; i < 2; i++) {
				children[i] = fork();
				if (children[i] < 0)
					fail("extended fork");
				if (!children[i]) {
					char token;
					if (read(pipes[i][0], &token, 1) != 1)
						_exit(31);
					verify(maps[1], 0, BYTES);
					if (close(fd) || munmap((char *)maps[0] + BLOCK, 4096))
						_exit(32);
					if (!i && (munmap(maps[0], BYTES) || munmap(maps[1], BYTES)))
						_exit(33);
					/* Sibling 1 leaves both VMAs to real exit_mmap. */
					_exit(0);
				}
				ready[i] = pipes[i][1];
			}
			if (close(fd) || munmap(maps[0], BYTES) || munmap(maps[1], BYTES) ||
			    ioctl(factory, DMA_AUDIT_EXPORT_LIVE, 0) != 1 ||
			    ioctl(factory, DMA_AUDIT_EXPORT_TABLE_BYTES, 0) != before)
				fail("parent cleanup lost child backing or parent tables");
			printf("DMA_EXT_PARENT_PASS mode=%u round=%u child_holds=2 tables_restored=1\n", mode, round);
			/* Both children are released together; final teardown can race. */
			for (unsigned int i = 0; i < 2; i++)
				if (write(ready[i], "x", 1) != 1)
					fail("extended child release");
			for (unsigned int i = 0; i < 2; i++) {
				if (waitpid(children[i], &status, 0) != children[i] ||
				    !WIFEXITED(status) || WEXITSTATUS(status))
					fail("extended child teardown");
				close(pipes[i][0]);
				close(pipes[i][1]);
			}
			wait_export_empty(factory);
			if (ioctl(factory, DMA_AUDIT_EXPORT_TABLE_BYTES, 0) != before)
				fail("extended tables changed after child exits");
			printf("DMA_EXT_LIFETIME_PASS mode=%u round=%u children=2 explicit_unmap=1 exit_mmap=1 live=0\n", mode, round);
		}
	}
	if (close(factory))
		fail("extended factory close");
	puts("DMA_EXT_END faults=8 lifetime=16 children=32");
}

int main(int argc, char **argv)
{
	struct utsname name;
	char compatible[128] = {0};
	int fd;
	ssize_t length;
	setvbuf(stdout, NULL, _IONBF, 0);
	if (argc != 2 || strcmp(argv[1], "--disposable-qemu-vm"))
		fail("explicit disposable VM invocation required");
	if (uname(&name) || strcmp(name.machine, "aarch64") || sysconf(_SC_PAGESIZE) != 4096)
		fail("ARM64/4K VM required");
	fd = open("/sys/firmware/devicetree/base/compatible", O_RDONLY);
	if (fd < 0)
		fail("VM compatible missing");
	length = read(fd, compatible, sizeof(compatible) - 1);
	close(fd);
	if (length < 16 || memcmp(compatible, "linux,dummy-virt", 16))
		fail("QEMU virt DT required; refuse phone");
	exercise("/dev/recovered-dma-audit-pmd", 0);
	exercise("/dev/recovered-dma-audit-pte", 0);
	exercise("/dev/recovered-dma-audit-fault-pmd", 1);
	exercise("/dev/recovered-dma-audit-fault-pte", 1);
	exercise("/dev/recovered-dma-audit-first-pmd", 1);
	exercise("/dev/recovered-dma-audit-first-pte", 1);
	exercise("/dev/recovered-dma-audit-table-pmd", 1);
	exercise("/dev/recovered-dma-audit-table-pte", 1);
	exercise("/dev/recovered-dma-audit-table-cross-pmd", 1);
	exercise("/dev/recovered-dma-audit-table-cross-pte", 1);
	exercise_export(0);
	exercise_export(1);
	exercise_extended();
	exercise_vma_failures();
	puts("DMA_GUEST_PASS: basic mmap/fork/move/split/lifetime/SMP workload only");
	return 0;
}
