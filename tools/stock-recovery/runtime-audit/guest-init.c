// SPDX-License-Identifier: GPL-2.0-only
/* Minimal PID1 for disposable QEMU RAM-only audit. Never a phone init. */
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/wait.h>
#include <unistd.h>

static void fatal(const char *reason)
{
	fprintf(stderr, "DMA_VM_RESULT_FAIL: %s errno=%d\n", reason, errno);
	exit(1); /* PID1 panic is a failure; runner must stop the VM on timeout. */
}

static void make_audit_node(const char *name)
{
	char source[128], target[128], extra;
	unsigned int major_number, minor_number;
	FILE *stream;

	if (snprintf(source, sizeof(source), "/sys/class/misc/%s/dev", name) >= (int)sizeof(source) ||
	    snprintf(target, sizeof(target), "/dev/%s", name) >= (int)sizeof(target))
		fatal("node name too long");
	stream = fopen(source, "r");
	if (!stream)
		fatal("audit sysfs dev missing");
	if (fscanf(stream, "%u:%u %c", &major_number, &minor_number, &extra) != 2 ||
	    major_number != 10 || minor_number > 255)
		fatal("unexpected misc device numbers");
	fclose(stream);
	if (mknod(target, S_IFCHR | 0600, makedev(major_number, minor_number)))
		fatal("create audit node");
}

int main(void)
{
	pid_t child;
	int status;
	setvbuf(stdout, NULL, _IONBF, 0);
	if (getpid() != 1)
		fatal("disposable guest PID1 required");
	if (mount("proc", "/proc", "proc", MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL) ||
	    mount("sysfs", "/sys", "sysfs", MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL))
		fatal("mount guest technical filesystems");
	make_audit_node("recovered-dma-audit-pmd");
	make_audit_node("recovered-dma-audit-pte");
	make_audit_node("recovered-dma-audit-fault-pmd");
	make_audit_node("recovered-dma-audit-fault-pte");
	make_audit_node("recovered-dma-audit-first-pmd");
	make_audit_node("recovered-dma-audit-first-pte");
	make_audit_node("recovered-dma-export-audit");
	child = fork();
	if (child < 0)
		fatal("start guest workload");
	if (!child) {
		execl("/guest", "guest", "--disposable-qemu-vm", (char *)NULL);
		fatal("exec guest workload");
	}
	if (waitpid(child, &status, 0) != child || !WIFEXITED(status) || WEXITSTATUS(status))
		fatal("guest workload failed");
	puts("DMA_VM_RESULT_PASS: workload completed; not full DMA/hardware proof");
	fflush(NULL);
	if (reboot(RB_POWER_OFF))
		fatal("guest poweroff");
	for (;;)
		pause();
}
