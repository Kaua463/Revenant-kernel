#!/usr/bin/env python3
"""Fail closed if the resolved config differs from stock KFENCE policy."""
import sys
from pathlib import Path

EXPECTED = {
    "CONFIG_KFENCE": "y",
    "CONFIG_KFENCE_SAMPLE_INTERVAL": "500",
    "CONFIG_KFENCE_NUM_OBJECTS": "63",
    "CONFIG_KFENCE_STATIC_KEYS": "n",
}


def validate(text):
    values = {}
    for line in text.splitlines():
        if line.startswith("CONFIG_") and "=" in line:
            key, value = line.split("=", 1)
        elif line.startswith("# CONFIG_") and line.endswith(" is not set"):
            key, value = line[2:-11], "n"
        else:
            continue
        if key in EXPECTED:
            if key in values:
                raise ValueError(f"Duplicate setting: {key}")
            values[key] = value
    for key, value in EXPECTED.items():
        if values.get(key) != value:
            raise ValueError(f"{key}: expected {value}, got {values.get(key, 'missing')}")


if __name__ == "__main__":
    validate(Path(sys.argv[1]).read_text())
    print("Stock KFENCE config verified; performance remains unproven.")
