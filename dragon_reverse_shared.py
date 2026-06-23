"""Pure helpers shared by Dragon Reverse tooling.

This module intentionally has no IDA dependency so it can be unit-tested from a
normal Python interpreter.
"""

from __future__ import annotations

import re
from typing import Any


COMMON_CUSTOM_IOCTL_DEVICE_TYPES = {0x22}

IOCTL_METHODS = {
    0: "METHOD_BUFFERED",
    1: "METHOD_IN_DIRECT",
    2: "METHOD_OUT_DIRECT",
    3: "METHOD_NEITHER",
}

IOCTL_ACCESS = {
    0: "FILE_ANY_ACCESS",
    1: "FILE_READ_ACCESS",
    2: "FILE_WRITE_ACCESS",
    3: "FILE_READ_WRITE_ACCESS",
}

EXACT_SIGNAL_TOKENS = {
    "in", "out", "ins", "outs", "cli", "sti", "try", "__try",
    "wd", "ba", "sy", "%p", "pci", "acpi", "wpp", "cr0",
}


def severity_from_score(score: int) -> str:
    if score >= 55:
        return "Critical"
    if score >= 35:
        return "High"
    if score >= 18:
        return "Medium"
    if score >= 8:
        return "Low"
    return "Info"


def decode_ioctl_value(value: int | None) -> dict[str, Any] | None:
    if value is None or value <= 0 or value > 0xFFFFFFFF:
        return None
    method = value & 0x3
    function = (value >> 2) & 0xFFF
    access = (value >> 14) & 0x3
    device_type = (value >> 16) & 0xFFFF
    if device_type == 0:
        return None
    if device_type < 0x8000 and device_type not in COMMON_CUSTOM_IOCTL_DEVICE_TYPES:
        return None
    if function < 0x100:
        return None
    suspicious = access == 0 or method == 3 or function >= 0x800 or device_type >= 0x8000
    if not suspicious:
        return None
    confidence = "high" if device_type >= 0x8000 or device_type in COMMON_CUSTOM_IOCTL_DEVICE_TYPES else "medium"
    return {
        "value": value,
        "hex": "0x%08X" % value,
        "device_type": device_type,
        "function": function,
        "function_code": function,
        "method": IOCTL_METHODS.get(method, str(method)),
        "access": IOCTL_ACCESS.get(access, str(access)),
        "suspicious": suspicious,
        "confidence": confidence,
    }


def signal_matches(signal: str, item: str) -> bool:
    sig = signal.lower()
    value = item.lower()
    if not sig or not value:
        return False
    if sig in EXACT_SIGNAL_TOKENS or len(sig) <= 3:
        return value == sig or value.endswith("!" + sig)
    if "\\" in sig or " " in sig or "%" in sig or "?" in sig:
        return sig in value
    if value == sig or value.endswith("!" + sig) or value.endswith("_" + sig):
        return True
    if re.match(r"^[a-z_][a-z0-9_]*$", sig):
        return bool(re.search(r"(^|[^a-z0-9_])%s([^a-z0-9_]|$)" % re.escape(sig), value))
    return sig in value


def matching_signals(candidates: list[str] | set[str], signal_set: set[str]) -> list[str]:
    hits: list[str] = []
    for signal in candidates:
        if any(signal_matches(signal, item) for item in signal_set):
            hits.append(signal)
    return hits
