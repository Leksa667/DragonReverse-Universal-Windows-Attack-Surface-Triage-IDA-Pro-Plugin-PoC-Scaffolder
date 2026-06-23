"""Pure Dragon Reverse logic for IDA plugin and unit tests.

No IDA imports are allowed here. Keep scoring helpers deterministic so they can
be tested outside IDA.
"""

from __future__ import annotations

import re
from typing import Any


SEVERITY_ORDER = {"Critical": 5, "High": 4, "Medium": 3, "Low": 2, "Info": 1}
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

COPY_ONLY_TOKENS = {"memcpy", "memmove", "RtlCopyMemory", "RtlMoveMemory", "memset"}
REGISTRY_WRITE_TOKENS = {"ZwCreateKey", "ZwSetValueKey", "RtlWriteRegistryValue"}
USER_POINTER_TOKENS = {
    "METHOD_NEITHER", "Type3InputBuffer", "UserBuffer", "SystemBuffer",
    "InputBufferLength", "OutputBufferLength", "Parameters.DeviceIoControl",
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


def profile_key(value: str) -> str:
    return re.sub(r"[^a-z0-9.]+", "", (value or "").lower())


def match_filename_profile(filename: str, profiles: dict[str, Any]) -> dict[str, Any] | None:
    if not isinstance(profiles, dict):
        return None
    name = (filename or "").split("\\")[-1].split("/")[-1].lower()
    normalized = profile_key(name)
    candidates = {name, normalized}
    for key, profile in profiles.items():
        if not isinstance(profile, dict):
            continue
        keys = {str(key).lower(), profile_key(str(key))}
        for alias in profile.get("aliases", []) or []:
            keys.add(str(alias).lower())
            keys.add(profile_key(str(alias)))
        if candidates & keys:
            out = dict(profile)
            out.setdefault("name", key)
            out["matched_filename"] = filename
            out["profile_key"] = key
            out["match_confidence"] = "filename-only"
            return out
    return None


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


def family_hit_actionable(family_id: str, hits: set[str], has_ioctls: bool, text_pool: set[str]) -> tuple[bool, str]:
    if family_id == "method_neither_user_pointer":
        if set(hits).issubset(COPY_ONLY_TOKENS) and not has_ioctls:
            if not any(signal_matches(token, item) for token in USER_POINTER_TOKENS for item in text_pool):
                return False, "suppressed-copy-only-user-pointer-fp"
    if family_id == "unsafe_copy_length":
        if not any(signal_matches(token, item) for token in USER_POINTER_TOKENS for item in text_pool):
            return False, "suppressed-copy-without-user-length-fp"
    if family_id == "registry_service_write":
        if not any(hit in REGISTRY_WRITE_TOKENS for hit in hits):
            return False, "registry-open-only-not-write"
    return True, ""


def add_compound_correlations(rows: list[dict[str, Any]], family_scores: dict[str, dict[str, Any]], known_profile: dict[str, Any] | None, known_source: str = "") -> list[dict[str, Any]]:
    patterns = [
        (
            "weak_device_to_memory_primitive",
            "Weak device exposure plus memory primitive",
            {"weak_device_acl"},
            {"physmem_map", "kernel_memory_rw", "mdl_dma_surface", "physical_section_object"},
            "If the device is openable by a low-privileged user and the memory primitive is reachable, this is the highest-value BYOVD review path.",
        ),
        (
            "ioctl_user_pointer_to_sink",
            "IOCTL/user-buffer surface plus sensitive sink",
            {"method_neither_user_pointer"},
            {"physmem_map", "kernel_memory_rw", "process_token_sensitive", "process_kill", "registry_service_write", "kernel_patch_or_exec_mapping"},
            "Prioritize data-flow: user buffer/length -> sensitive sink -> missing authorization or incomplete validation.",
        ),
        (
            "hardware_control_bundle",
            "Hardware control bundle",
            {"port_io"},
            {"msr_control", "firmware_pci_config", "physmem_map"},
            "Hardware utility pattern. Verify whether IOCTL inputs select MSR index, port/register offset, physical range, width, or write value.",
        ),
        (
            "process_control_bundle",
            "Process control / protection bypass bundle",
            {"process_token_sensitive"},
            {"process_kill", "callback_or_filter_tamper", "security_descriptor_write"},
            "Process/EDR-bypass pattern. Use only owned harmless test processes for dynamic proof until authorization boundaries are clear.",
        ),
    ]
    present = set(family_scores)
    for family, name, required, any_of, review in patterns:
        if not required.issubset(present) or not (any_of & present):
            continue
        functions: list[dict[str, Any]] = []
        evidence: set[str] = set()
        roles: set[str] = set()
        raw_score = 0
        for fid in sorted(required | (any_of & present)):
            bucket = family_scores.get(fid, {})
            raw_score += int(bucket.get("score", 0))
            evidence.update(bucket.get("evidence", set()))
            roles.update(bucket.get("roles", set()))
            for fn in bucket.get("functions", []):
                if len(functions) < 14 and fn not in functions:
                    functions.append(fn)
        confidence = min(100, 58 + min(raw_score // 8, 34) + min(len(roles) * 2, 8))
        rows.append({
            "family": family,
            "name": name,
            "confidence": confidence,
            "confidence_reason": "compound correlation: %s + %s" % (", ".join(sorted(required)), ", ".join(sorted(any_of & present))),
            "severity": severity_from_score(confidence // 2),
            "functions": functions,
            "roles": sorted(roles),
            "evidence": sorted(evidence)[:24],
            "review": review,
            "compound": True,
        })
    profile = known_profile or {}
    primitives = profile.get("primitives", []) or []
    if primitives:
        confidence = 75 if known_source == "sha256" else 52
        rows.append({
            "family": "profile_guided_review",
            "name": "Known BYOVD primitive profile",
            "confidence": confidence,
            "confidence_reason": "known profile source=%s primitives=%s" % (known_source or "unknown", ", ".join(primitives[:6])),
            "severity": severity_from_score(confidence // 2),
            "functions": [],
            "roles": [],
            "evidence": ["profile primitives: " + ", ".join(primitives[:10])],
            "review": "Use the profile as a search checklist. Confirm with function-level evidence before reporting.",
            "compound": True,
        })
    return rows
