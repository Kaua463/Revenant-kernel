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
	atomic_int stop;
	atomic_ulong passes;
};

static void *read_alias(void *argument)
{
	struct reader *reader = argument;
	while (!atomic_load_explicit(&reader->stop, memory_order_acquire)) {
		verify(reader->alias, 0, BYTES);
		atomic_fetch_add_explicit(&reader->passes, 1, memory_order_relaxed);
	}
	return NULL;
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

static void exercise(const char *device)
{
	int fd = open(device, O_RDWR | O_CLOEXEC), status;
	void *first, *alias, *target, *moved;
	pid_t child;
	pthread_t thread;
	struct reader reader;

	if (fd < 0)
		fail("open audit device");
	reject(fd, 3 * 1024 * 1024, PROT_READ, MAP_SHARED, 0);
	reject(fd, BLOCK, PROT_READ, MAP_PRIVATE, 0);
	reject(fd, BLOCK, PROT_READ | PROT_EXEC, MAP_SHARED, 0);
	reject(fd, BYTES, PROT_READ, MAP_SHARED, BLOCK);
	reject(fd, BLOCK, PROT_READ, MAP_SHARED, BYTES);
	first = map_owned(fd);
	alias = map_owned(fd);
	audit_fill(first, BYTES, SEED);
	verify(alias, 0, BYTES);
	if (close(fd))
		fail("close mapped file");
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
	reader.alias = alias;
	atomic_init(&reader.stop, 0);
	atomic_init(&reader.passes, 0);
	if (pthread_create(&thread, NULL, read_alias, &reader))
		fail("reader create");
	target = reservation(BYTES);
	moved = mremap(first, BYTES, BYTES, MREMAP_MAYMOVE | MREMAP_FIXED, target);
	if (moved != target)
		fail("move mapping");
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
	exercise("/dev/recovered-dma-audit-pmd");
	exercise("/dev/recovered-dma-audit-pte");
	puts("DMA_GUEST_PASS: basic mmap/fork/move/split/lifetime/SMP workload only");
	return 0;
}
