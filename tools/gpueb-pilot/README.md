# GPUEB pilot: offline review, 2026-10-01

Only the first 64 bytes at physical 0x13c00000 are read. The mapping covers
one 4 KiB page and ends before the GPR/mailbox regions. No parameters can
expand the address or size. No physical writes, IPI, clock, voltage, reset,
watchdog or power-control operations are implemented.

Initialization verifies the enabled `mediatek,gpueb` DT node and the names,
addresses and lengths of resources 0 (gpueb_base), 1 (gpueb_gpr_base) and
4 (mbox0_base). These indices match the extracted rodin vendor_boot DT;
the previous live check established only the first two resource tuples.
The new mailbox check must still pass on the device.

The proc file is mode 0400. Each read also requires CAP_SYS_RAWIO. Zero-size,
negative-position and EOF requests cause no MMIO access. Seeking is disabled.
A mutex serializes capture. At most one 64-byte hardware capture occurs per
module load; subsequent opens/reads use the cached snapshot, including after
a failed copy to userspace. `proc_remove` removes the interface on unload.

## What offline checks cannot establish

- DT presence and a successful ioremap do not establish AP access permission.
- The driver reports Active from g_shared_status; this is not a power hold.
  Power may change after the host check. No validated, read-only runtime
  power interlock was found; none is invented here.
- Byte reads retain the original pilot's access width. The documented DT
  does not establish supported SRAM bus widths or absence of DEVAPC/MPU
  protection. A bus abort/reboot remains possible during the first read.
- Compilation/modpost/vermagic do not prove that insmod will be accepted by
  the running kernel's protected-symbol and signature policy.
- This is a pilot, not a complete SRAM dump or proof of decrypted firmware.

The host capture script checks artifact hash, ELF architecture/name/release,
pins the selected ADB serial, checks GPU state before and after loading,
uses a private temporary directory and verifies the transferred hash.
Cleanup failure returns failure even if 64 bytes were captured. SELinux
restoration is attempted after any request to change it, including timeout.
Successful capture is never claimed as hardware validation before execution.
