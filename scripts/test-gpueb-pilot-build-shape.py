#!/usr/bin/env python3
"""Fail fast if the bounded GPUEB pilot cannot be built by Kleaf."""

from pathlib import Path


root = Path(__file__).resolve().parents[1]
pilot = root / "tools/gpueb-pilot"
makefile = (pilot / "Makefile").read_text()
kbuild = (pilot / "Kbuild").read_text()
bazel = (pilot / "BUILD.bazel").read_text()
reader = (pilot / "gpueb_sram_pilot.c").read_text()

assert "obj-m += gpueb_sram_pilot.o" in kbuild
assert '"Kbuild"' in bazel and '"Makefile"' in bazel
assert "all: modules" in makefile
assert "modules:" in makefile and "modules_install:" in makefile
assert "$(MAKE) -C $(KERNEL_SRC) M=$(M) O=$(O) modules" in makefile
assert "INSTALL_MOD_DIR=$(INSTALL_MOD_DIR) modules_install" in makefile

assert "#define GPUEB_BASE 0x13c00000ULL" in reader
assert "#define PILOT_SIZE 64U" in reader
assert "#define FIRST_REG 0x13c4fd1cULL" in reader
assert "BUILD_BUG_ON(GPUEB_BASE + SZ_4K > FIRST_REG)" in reader
assert "snapshot[i] = readb(mapped + i)" in reader
assert "capable(CAP_SYS_RAWIO)" in reader
assert "if (!count || *pos >= PILOT_SIZE)" in reader
assert "mutex_lock_interruptible(&pilot_lock)" in reader
assert "if (snapshot_valid)" in reader
assert ".proc_lseek = no_llseek" in reader
for index in (0, 1, 4):
    assert f"of_address_to_resource(node, {index}, &resource)" in reader
for forbidden in ("writeb(", "writew(", "writel(", "memcpy_toio("):
    assert forbidden not in reader

print("GPUEB pilot build shape and read bounds ok")
