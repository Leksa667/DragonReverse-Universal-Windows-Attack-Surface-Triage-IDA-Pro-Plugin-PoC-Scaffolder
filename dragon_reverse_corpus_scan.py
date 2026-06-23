#!/usr/bin/env python3
"""Offline corpus scanner for Dragon Reverse.

The script indexes local driver folders and emits JSON/Markdown reports with
hashes, PE imports/exports, strings, and static triage signals. It is a triage
tool for authorized research, not an exploit generator.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import struct
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    from dragon_reverse_shared import matching_signals
except ImportError:
    from tools.dragon_reverse_shared import matching_signals


DEFAULT_DIRS = ["Driver vulnerable", "Driver suspect", "Driver to test"]

RISK_WEIGHTS = {
    "MmMapIoSpace": 12,
    "MmMapIoSpaceEx": 14,
    "MmMapLockedPagesSpecifyCache": 11,
    "MmGetPhysicalAddress": 8,
    "MmAllocateContiguousMemory": 6,
    "MmAllocateContiguousNodeMemory": 6,
    "ZwMapViewOfSection": 9,
    "ZwOpenSection": 6,
    "ZwCreateSection": 7,
    "MmMapViewInSystemSpace": 8,
    "MmUnmapViewInSystemSpace": 4,
    "ZwOpenKey": 7,
    "ZwCreateKey": 7,
    "ZwSetValueKey": 9,
    "RtlWriteRegistryValue": 9,
    "IoCreateDevice": 5,
    "IoCreateSymbolicLink": 5,
    "IoCreateDeviceSecure": -3,
    "IoValidateDeviceIoControlAccess": -8,
    "SeSinglePrivilegeCheck": -8,
    "SePrivilegeCheck": -8,
    "ProbeForRead": -2,
    "ProbeForWrite": -2,
    "MmCopyMemory": 5,
    "MmCopyVirtualMemory": 9,
    "IoAllocateMdl": 5,
    "MmProbeAndLockPages": 7,
    "MmBuildMdlForNonPagedPool": 5,
    "ObReferenceObjectByHandle": 5,
    "ObOpenObjectByPointer": 6,
    "PsLookupProcessByProcessId": 6,
    "PsReferencePrimaryToken": 8,
    "PsReferenceImpersonationToken": 7,
    "PsImpersonateClient": 8,
    "ZwOpenProcess": 6,
    "ZwOpenThread": 5,
    "ZwTerminateProcess": 10,
    "TerminateProcess": 8,
    "PsTerminateSystemThread": 4,
    "PROCESS_TERMINATE": 6,
    "ZwDuplicateObject": 5,
    "ZwSetSecurityObject": 7,
    "RtlSetDaclSecurityDescriptor": 7,
    "RtlAddAccessAllowedAce": 6,
    "SeCaptureSecurityDescriptor": 4,
    "SeAccessCheck": -4,
    "SeImpersonateClient": 7,
    "SeCreateClientSecurity": 6,
    "PsSetCreateProcessNotifyRoutine": 5,
    "PsSetCreateThreadNotifyRoutine": 5,
    "PsSetLoadImageNotifyRoutine": 5,
    "ObRegisterCallbacks": 5,
    "CmRegisterCallback": 5,
    "FltRegisterFilter": 4,
    "FltCreateCommunicationPort": 7,
    "FltBuildDefaultSecurityDescriptor": -5,
    "FltSendMessage": 5,
    "FltGetMessage": 5,
    "FltReplyMessage": 5,
    "IoGetDmaAdapter": 7,
    "AllocateAdapterChannel": 7,
    "MapTransfer": 7,
    "FlushAdapterBuffers": 4,
    "FreeAdapterChannel": 3,
    "BuildScatterGatherList": 6,
    "HalGetBusData": 7,
    "HalSetBusData": 8,
    "HalGetBusDataByOffset": 7,
    "HalSetBusDataByOffset": 8,
    "ExGetFirmwareEnvironmentVariable": 8,
    "ExSetFirmwareEnvironmentVariable": 10,
    "ZwQuerySystemEnvironmentValue": 7,
    "ZwSetSystemEnvironmentValue": 10,
    "ZwSetSystemEnvironmentValueEx": 10,
    "ZwSetSystemInformation": 9,
    "ZwSystemDebugControl": 10,
    "ZwLoadDriver": 8,
    "ZwUnloadDriver": 7,
    "ZwSetInformationProcess": 7,
    "ZwSetInformationThread": 7,
    "IoSetCancelRoutine": 4,
    "IoCancelIrp": 3,
    "IoAcquireCancelSpinLock": 3,
    "IoInitializeRemoveLock": 2,
    "ExAcquireRundownProtection": -3,
    "IoReleaseRemoveLockAndWait": -3,
    "ExQueueWorkItem": 4,
    "IoQueueWorkItem": 4,
    "MmGetSystemRoutineAddress": 5,
    "MmProtectMdlSystemAddress": 7,
    "ZwProtectVirtualMemory": 8,
    "ZwCreateSymbolicLinkObject": 6,
    "ZwOpenSymbolicLinkObject": 5,
    "ZwCreateEvent": 4,
    "ZwOpenEvent": 4,
    "IoRegisterDeviceInterface": 4,
    "IoWMIRegistrationControl": 5,
    "WmiSystemControl": 5,
    "ZwAlpcCreatePort": 7,
    "ZwAlpcConnectPort": 5,
    "ZwAlpcSendWaitReceivePort": 6,
    "ExAllocatePoolWithTag": 2,
    "memcpy": 3,
    "memmove": 3,
    "strcpy": 4,
    "sprintf": 4
}

BYTE_PATTERNS = {
    "CurrentControlSet\\Services": b"CurrentControlSet\\Services",
    "DosDevices": b"\\DosDevices\\",
    "Device namespace": b"\\Device\\",
    "PhysicalMemory section": b"\\Device\\PhysicalMemory",
    "BaseNamedObjects namespace": b"\\BaseNamedObjects\\",
    "GLOBAL?? namespace": b"\\GLOBAL??\\",
    "METHOD_NEITHER": b"METHOD_NEITHER",
    "FILE_ANY_ACCESS": b"FILE_ANY_ACCESS",
    "PAGE_EXECUTE_READWRITE": b"PAGE_EXECUTE_READWRITE",
    "KernelMode string": b"KernelMode",
    "UserMode string": b"UserMode"
}

MITIGATION_SIGNALS = {
    "IoCreateDeviceSecure",
    "IoValidateDeviceIoControlAccess",
    "SeSinglePrivilegeCheck",
    "SePrivilegeCheck",
    "SeAccessCheck",
    "ProbeForRead",
    "ProbeForWrite",
    "ExGetPreviousMode",
    "FltBuildDefaultSecurityDescriptor",
    "ExAcquireRundownProtection",
    "IoReleaseRemoveLockAndWait",
    "RtlSizeTAdd",
    "RtlULongAdd"
}

LOCAL_KNOWN_FILENAMES = {
    "asmiO64.sys".lower(),
    "asrdrv.sys",
    "devmemdrv.sys",
    "driver_win10.sys",
    "iqvw64e.sys",
    "phymemx64.sys",
    "rtcore64.sys",
    "vboxdrv.sys",
    "whql.sys",
    "ipt.sys"
}

CORE_WINDOWS_DRIVER_NAMES = {
    "ahcache.sys", "appid.sys",
    "acpi.sys", "afd.sys", "ataport.sys", "classpnp.sys", "cng.sys", "disk.sys",
    "dxgkrnl.sys", "dxgmms1.sys", "dxgmms2.sys", "fltmgr.sys", "fvevol.sys",
    "http.sys", "ipnat.sys", "ks.sys", "netbt.sys", "portcls.sys", "rdbss.sys",
    "rdpdr.sys", "refs.sys", "scsiport.sys", "spaceport.sys", "vid.sys",
    "vhdmp.sys", "wdfilter.sys", "wddevflt.sys", "wdnisdrv.sys", "wudfrd.sys",
    "wudfpf.sys", "xboxgip.sys",
    "http.sys", "ndis.sys", "netio.sys", "ntfs.sys", "pci.sys", "storport.sys",
    "tcpip.sys", "usbport.sys", "usbxhci.sys", "vmbus.sys", "volmgr.sys",
    "volsnap.sys", "wdf01000.sys", "winhv.sys"
}

FAMILY_RULES = [
    ("physmem_map", 1, 12, ["MmMapIoSpace", "MmMapIoSpaceEx", "MmMapLockedPagesSpecifyCache", "MmGetPhysicalAddress", "MmAllocateContiguousMemory"]),
    ("msr_control", 1, 14, ["wrmsr", "rdmsr", "__writemsr", "__readmsr"]),
    ("registry_service_write", 1, 10, ["ZwSetValueKey", "RtlWriteRegistryValue", "CurrentControlSet\\Services", "Registry\\Machine\\System"]),
    ("weak_device_acl", 2, 8, ["IoCreateDevice", "IoCreateSymbolicLink", "\\DosDevices\\", "\\Device\\"]),
    ("method_neither_user_pointer", 2, 10, ["METHOD_NEITHER", "Type3InputBuffer", "UserBuffer", "ProbeForRead", "ProbeForWrite", "memcpy", "memmove", "RtlCopyMemory"]),
    ("kernel_memory_rw", 2, 12, ["MmCopyVirtualMemory", "MmCopyMemory", "ZwMapViewOfSection", "IoAllocateMdl", "MmProbeAndLockPages", "PsLookupProcessByProcessId", "ObReferenceObjectByHandle"]),
    ("mdl_dma_surface", 2, 12, ["IoAllocateMdl", "MmProbeAndLockPages", "MmBuildMdlForNonPagedPool", "MmMapLockedPagesSpecifyCache", "IoGetDmaAdapter", "GetScatterGatherList", "BuildScatterGatherList", "AllocateCommonBuffer"]),
    ("process_token_sensitive", 2, 13, ["PsLookupProcessByProcessId", "PsReferencePrimaryToken", "PsReferenceImpersonationToken", "ZwOpenProcess", "ZwOpenThread", "ObOpenObjectByPointer", "ObReferenceObjectByHandle", "SeAccessCheck"]),
    ("process_kill", 2, 12, ["ZwTerminateProcess", "TerminateProcess", "PROCESS_TERMINATE", "ZwOpenProcess", "PsLookupProcessByProcessId", "ObReferenceObjectByHandle"]),
    ("security_descriptor_write", 1, 8, ["ZwSetSecurityObject", "RtlSetDaclSecurityDescriptor", "RtlCreateSecurityDescriptor", "RtlAddAccessAllowedAce", "SeCaptureSecurityDescriptor", "SeAssignSecurity"]),
    ("callback_or_filter_tamper", 1, 7, ["PsSetCreateProcessNotifyRoutine", "PsSetCreateThreadNotifyRoutine", "PsSetLoadImageNotifyRoutine", "ObRegisterCallbacks", "CmRegisterCallback", "FltRegisterFilter"]),
    ("firmware_pci_config", 2, 8, ["HalGetBusData", "HalSetBusData", "HalGetBusDataByOffset", "HalSetBusDataByOffset", "IRP_MN_READ_CONFIG", "IRP_MN_WRITE_CONFIG", "SMBIOS", "ACPI", "PCI"]),
    ("physical_section_object", 2, 14, ["\\Device\\PhysicalMemory", "ZwOpenSection", "ZwCreateSection", "ZwMapViewOfSection", "MmMapViewInSystemSpace", "SECTION_MAP_READ", "SECTION_MAP_WRITE"]),
    ("firmware_environment", 1, 12, ["ExGetFirmwareEnvironmentVariable", "ExSetFirmwareEnvironmentVariable", "ZwQuerySystemEnvironmentValue", "ZwSetSystemEnvironmentValue", "ZwSetSystemEnvironmentValueEx"]),
    ("legacy_dma_adapter", 2, 10, ["IoGetDmaAdapter", "AllocateAdapterChannel", "MapTransfer", "FlushAdapterBuffers", "FreeAdapterChannel", "GetScatterGatherList", "BuildScatterGatherList", "DmaOperations"]),
    ("system_information_write", 1, 13, ["ZwSetSystemInformation", "ZwSystemDebugControl", "ZwLoadDriver", "ZwUnloadDriver", "ZwSetInformationProcess", "ZwSetInformationThread"]),
    ("minifilter_user_comm", 2, 9, ["FltCreateCommunicationPort", "FltCloseCommunicationPort", "FltSendMessage", "FltGetMessage", "FltReplyMessage", "FltRegisterFilter", "FltStartFiltering"]),
    ("lifetime_race_cancel", 3, 7, ["IoSetCancelRoutine", "IoCancelIrp", "IoAcquireCancelSpinLock", "IoReleaseCancelSpinLock", "IoInitializeRemoveLock", "IoAcquireRemoveLock", "IoReleaseRemoveLock", "ExQueueWorkItem", "IoQueueWorkItem"]),
    ("hypervisor_or_secure_kernel_surface", 2, 8, ["Hvl", "HvCall", "Vmb", "Vtl", "IsSecureKernel", "WinHv", "Vid", "VMBus", "SecureKernel"]),
    ("object_namespace_confusion", 2, 8, ["IoCreateSymbolicLink", "IoRegisterDeviceInterface", "ZwCreateSymbolicLinkObject", "ZwOpenSymbolicLinkObject", "ZwCreateEvent", "ZwOpenEvent", "ZwCreateSection", "ZwOpenSection", "\\BaseNamedObjects\\", "\\GLOBAL??\\"]),
    ("impersonation_boundary", 2, 11, ["SeImpersonateClient", "PsImpersonateClient", "SeCreateClientSecurity", "SeCreateClientSecurityFromSubjectContext", "PsReferenceImpersonationToken", "SECURITY_CLIENT_CONTEXT"]),
    ("kernel_patch_or_exec_mapping", 2, 12, ["MmGetSystemRoutineAddress", "MmProtectMdlSystemAddress", "ZwProtectVirtualMemory", "PAGE_EXECUTE_READWRITE", "CR0", "WriteProtect", "PsInitialSystemProcess"]),
    ("wmi_etw_control_plane", 2, 7, ["IoWMIRegistrationControl", "WmiSystemControl", "EtwRegister", "EtwWrite", "TraceLoggingWrite", "WMIREGINFO"]),
    ("alpc_port_boundary", 2, 10, ["ZwAlpcCreatePort", "ZwAlpcConnectPort", "ZwAlpcSendWaitReceivePort", "ALPC_PORT_ATTRIBUTES", "ALPC_MESSAGE_ATTRIBUTES"])
]


def read_u16(data: bytes, off: int) -> int:
    if off + 2 > len(data):
        raise ValueError("short read")
    return struct.unpack_from("<H", data, off)[0]


def read_u32(data: bytes, off: int) -> int:
    if off + 4 > len(data):
        raise ValueError("short read")
    return struct.unpack_from("<I", data, off)[0]


def read_u64(data: bytes, off: int) -> int:
    if off + 8 > len(data):
        raise ValueError("short read")
    return struct.unpack_from("<Q", data, off)[0]


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    import math
    total = float(len(data))
    return -sum((c / total) * math.log2(c / total) for c in counts if c)


def decode_ascii(data: bytes, off: int, limit: int = 512) -> str:
    if off < 0 or off >= len(data):
        return ""
    end = data.find(b"\x00", off)
    if end < 0:
        end = min(len(data), off + limit)
    return data[off:end].decode("ascii", "replace")


def extract_printable_strings(data: bytes, min_len: int = 5, limit: int = 3000) -> list[str]:
    strings: list[str] = []
    for match in re.finditer(rb"[\x20-\x7e]{%d,}" % min_len, data):
        text = match.group(0).decode("ascii", "replace")
        if any(token in text for token in ("\\Device\\", "\\DosDevices\\", "CurrentControlSet", "IOCTL", "METHOD_", "FILE_")):
            strings.append(text[:240])
        if len(strings) >= limit:
            break
    return sorted(set(strings))


@dataclass
class Section:
    name: str
    va: int
    vsize: int
    raw: int
    raw_size: int
    chars: int


class PEView:
    def __init__(self, data: bytes):
        self.data = data
        self.valid = False
        self.machine = ""
        self.timestamp = 0
        self.image_base = 0
        self.subsystem = 0
        self.is64 = False
        self.sections: list[Section] = []
        self.imports: list[dict[str, Any]] = []
        self.exports: list[str] = []
        self._parse()

    def rva_to_off(self, rva: int) -> int | None:
        for sec in self.sections:
            span = max(sec.vsize, sec.raw_size)
            if sec.va <= rva < sec.va + span:
                off = sec.raw + (rva - sec.va)
                if 0 <= off < len(self.data):
                    return off
        if 0 <= rva < len(self.data):
            return rva
        return None

    def cstr(self, rva: int) -> str:
        off = self.rva_to_off(rva)
        return decode_ascii(self.data, off if off is not None else -1)

    def _parse(self) -> None:
        data = self.data
        if len(data) < 0x100 or data[:2] != b"MZ":
            return
        peoff = read_u32(data, 0x3C)
        if peoff + 0x108 >= len(data) or data[peoff:peoff + 4] != b"PE\x00\x00":
            return
        self.valid = True
        machine = read_u16(data, peoff + 4)
        self.machine = {0x8664: "x64", 0x14C: "x86", 0xAA64: "arm64"}.get(machine, hex(machine))
        nsects = read_u16(data, peoff + 6)
        self.timestamp = read_u32(data, peoff + 8)
        opt_size = read_u16(data, peoff + 20)
        opt = peoff + 24
        magic = read_u16(data, opt)
        self.is64 = magic == 0x20B
        if self.is64:
            self.image_base = read_u64(data, opt + 24)
            self.subsystem = read_u16(data, opt + 92)
            dd = opt + 112
        else:
            self.image_base = read_u32(data, opt + 28)
            self.subsystem = read_u16(data, opt + 68)
            dd = opt + 96
        dirs = [(read_u32(data, dd + i * 8), read_u32(data, dd + i * 8 + 4)) for i in range(16)]
        sec_off = opt + opt_size
        for i in range(nsects):
            so = sec_off + i * 40
            name = data[so:so + 8].split(b"\x00", 1)[0].decode("ascii", "replace")
            self.sections.append(Section(name, read_u32(data, so + 12), read_u32(data, so + 8), read_u32(data, so + 20), read_u32(data, so + 16), read_u32(data, so + 36)))
        self._parse_imports(dirs[1][0])
        self._parse_exports(dirs[0][0])

    def _parse_imports(self, imp_rva: int) -> None:
        if not imp_rva:
            return
        imp_off = self.rva_to_off(imp_rva)
        if imp_off is None:
            return
        for n in range(512):
            d = imp_off + n * 20
            if d + 20 > len(self.data):
                break
            oft, _, _, name_rva, ft = struct.unpack_from("<IIIII", self.data, d)
            if oft == 0 and name_rva == 0 and ft == 0:
                break
            dll = self.cstr(name_rva)
            thunk_rva = oft or ft
            thunk_off = self.rva_to_off(thunk_rva)
            names: list[str] = []
            if thunk_off is not None:
                step = 8 if self.is64 else 4
                ordinal_mask = 0x8000000000000000 if self.is64 else 0x80000000
                for j in range(4096):
                    to = thunk_off + j * step
                    if to + step > len(self.data):
                        break
                    val = read_u64(self.data, to) if self.is64 else read_u32(self.data, to)
                    if val == 0:
                        break
                    if val & ordinal_mask:
                        names.append("#%d" % (val & 0xFFFF))
                    else:
                        no = self.rva_to_off(val)
                        name = decode_ascii(self.data, no + 2 if no is not None else -1)
                        if name:
                            names.append(name)
            self.imports.append({"dll": dll, "names": names})

    def _parse_exports(self, exp_rva: int) -> None:
        if not exp_rva:
            return
        exp_off = self.rva_to_off(exp_rva)
        if exp_off is None or exp_off + 40 > len(self.data):
            return
        try:
            _, _, _, _, _, _, _, nname, _, names_rva, _ = struct.unpack_from("<IIHHIIIIIII", self.data, exp_off)
            names_off = self.rva_to_off(names_rva)
            if names_off is None:
                return
            for i in range(min(nname, 4096)):
                nrva = read_u32(self.data, names_off + i * 4)
                name = self.cstr(nrva)
                if name:
                    self.exports.append(name)
        except Exception:
            return


def flatten_imports(pe: PEView) -> list[str]:
    return sorted({name for mod in pe.imports for name in mod.get("names", []) if name})


def score_driver(path: Path, data: bytes, imports: list[str], strings: list[str]) -> tuple[int, int, str, list[str], list[str], list[str], int, list[str]]:
    score = 0
    reasons: list[str] = []
    mitigations: list[str] = []
    notes: list[str] = []
    signal_set = set(imports)
    signal_set.update(strings)
    for name, weight in RISK_WEIGHTS.items():
        if matching_signals([name], signal_set):
            score += weight
            if weight < 0:
                mitigations.append(name)
            else:
                reasons.append(name)
    for label, pattern in BYTE_PATTERNS.items():
        if pattern.lower() in data.lower():
            score += 5 if "opcode" in label else 3
            reasons.append(label)
            signal_set.add(label)
            try:
                signal_set.add(pattern.decode("ascii", "ignore"))
            except Exception:
                pass
    lowered = path.name.lower()
    if lowered in LOCAL_KNOWN_FILENAMES:
        score += 15
        reasons.append("local vulnerable corpus filename")
    if "mem" in lowered or "io" in lowered or "msr" in lowered:
        score += 3
        reasons.append("risky filename token")

    families: list[str] = []
    family_hit_count = 0
    for family, min_hits, family_weight, signals in FAMILY_RULES:
        hits = matching_signals(signals, signal_set)
        if len(hits) >= min_hits:
            families.append(family)
            family_hit_count += len(hits)
            score += family_weight + min(len(hits), 4) * 2
            reasons.extend(hits[:6])

    mitigation_hits = matching_signals(MITIGATION_SIGNALS, signal_set)
    mitigations.extend(mitigation_hits)

    surface_hits = matching_signals([
        "IoCreateDevice", "IoCreateSymbolicLink", "\\DosDevices\\", "\\Device\\",
        "IRP_MJ_DEVICE_CONTROL", "Parameters.DeviceIoControl", "IoControlCode",
        "FltCreateCommunicationPort", "IoWMIRegistrationControl", "ZwAlpcCreatePort"
    ], signal_set)
    if surface_hits:
        score += min(len(surface_hits), 4) * 3
        reasons.extend(surface_hits)
    else:
        notes.append("No obvious user-reachable surface in imports/strings; require IDA xref confirmation.")
        if families:
            score = max(0, score - 10)

    if lowered in CORE_WINDOWS_DRIVER_NAMES and lowered not in LOCAL_KNOWN_FILENAMES:
        notes.append("Core Windows driver name; treat broad primitive imports as high false-positive risk until an exposed IOCTL/port path is proven.")
        if len(surface_hits) < 2:
            score = max(0, score - 22)

    mitigation_count = len(set(mitigations))
    if mitigation_count:
        notes.append("Mitigation signals present: %s" % ", ".join(sorted(set(mitigations))[:6]))

    confidence = 20 + min(score, 60) + min(family_hit_count * 2, 20)
    confidence += min(len(surface_hits) * 5, 15)
    confidence -= min(mitigation_count * 4, 20)
    if lowered in CORE_WINDOWS_DRIVER_NAMES and lowered not in LOCAL_KNOWN_FILENAMES:
        confidence -= 35
    if lowered in LOCAL_KNOWN_FILENAMES:
        confidence += 15
    confidence = max(1, min(100, confidence))

    false_positive_risk = "Low"
    if lowered in CORE_WINDOWS_DRIVER_NAMES and mitigation_count:
        false_positive_risk = "High"
    elif lowered in CORE_WINDOWS_DRIVER_NAMES or mitigation_count >= 4 or not surface_hits:
        false_positive_risk = "Medium"

    review_priority = int(score * 0.55 + confidence * 0.45)
    folder_name = path.parent.name.lower()
    if lowered in LOCAL_KNOWN_FILENAMES:
        review_priority += 120
    if folder_name == "driver vulnerable":
        review_priority += 35
    elif folder_name == "driver suspect":
        review_priority += 30
    if lowered in CORE_WINDOWS_DRIVER_NAMES and lowered not in LOCAL_KNOWN_FILENAMES:
        review_priority -= 140
    if not surface_hits:
        review_priority -= 45
    review_priority -= min(mitigation_count * 8, 48)
    if false_positive_risk == "High":
        review_priority -= 35
    elif false_positive_risk == "Medium":
        review_priority -= 15
    review_priority = max(0, review_priority)

    return score, review_priority, false_positive_risk, sorted(set(reasons)), sorted(set(families)), sorted(set(mitigations)), confidence, notes


def scan_file(path: Path, root: Path) -> dict[str, Any]:
    data = path.read_bytes()
    pe = PEView(data)
    imports = flatten_imports(pe)
    strings = extract_printable_strings(data)
    score, review_priority, false_positive_risk, reasons, families, mitigations, confidence, notes = score_driver(path, data, imports, strings)
    return {
        "folder": str(path.parent.relative_to(root)) if path.parent != root else ".",
        "file": path.name,
        "path": str(path),
        "size": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "md5": hashlib.md5(data).hexdigest(),
        "entropy": round(entropy(data), 3),
        "pe": pe.valid,
        "machine": pe.machine,
        "timestamp": pe.timestamp,
        "timestamp_utc": datetime.fromtimestamp(pe.timestamp, timezone.utc).isoformat() if pe.timestamp else "",
        "image_base": "0x%X" % pe.image_base if pe.image_base else "",
        "subsystem": pe.subsystem,
        "sections": [sec.__dict__ for sec in pe.sections],
        "imports_count": len(imports),
        "imports": imports,
        "exports": pe.exports,
        "interesting_strings": strings,
        "risk_score": score,
        "review_priority": review_priority,
        "confidence": confidence,
        "false_positive_risk": false_positive_risk,
        "risk_reasons": reasons,
        "mitigations": mitigations,
        "triage_notes": notes,
        "families": families
    }


def markdown_report(rows: list[dict[str, Any]], root: Path) -> str:
    rows_sorted = sorted(rows, key=lambda r: (r.get("review_priority", 0), r.get("confidence", 0), r.get("risk_score", 0)), reverse=True)
    by_folder: dict[str, int] = {}
    for row in rows:
        by_folder[row["folder"]] = by_folder.get(row["folder"], 0) + 1
    def cell(value: Any) -> str:
        return str(value).replace("|", "/").replace("\n", " ")[:600]
    lines = [
        "# Dragon Reverse Corpus Audit",
        "",
        "Generated: %s" % datetime.now(timezone.utc).isoformat(),
        "Root: `%s`" % root,
        "",
        "## Inventory",
        "",
        "| Folder | Count |",
        "| --- | ---: |"
    ]
    for folder, count in sorted(by_folder.items()):
        lines.append("| `%s` | %d |" % (folder, count))
    lines += [
        "",
        "## Highest Priority Drivers",
        "",
        "| Priority | Score | Confidence | FP risk | Driver | Folder | Families | Top reasons | Mitigations | Notes | SHA256 |",
        "| ---: | ---: | ---: | --- | --- | --- | --- | --- | --- | --- | --- |"
    ]
    for row in rows_sorted[:40]:
        reasons = ", ".join(row["risk_reasons"][:8])
        mitigations = ", ".join(row.get("mitigations", [])[:6])
        notes = " ".join(row.get("triage_notes", [])[:3])
        families = ", ".join(row["families"])
        lines.append("| %d | %d | %d | %s | `%s` | `%s` | %s | %s | %s | %s | `%s` |" % (
            row.get("review_priority", 0), row["risk_score"], row.get("confidence", 0),
            cell(row.get("false_positive_risk", "")), row["file"], row["folder"],
            cell(families), cell(reasons), cell(mitigations), cell(notes), row["sha256"]))
    lines += [
        "",
        "## Notes",
        "",
        "Scores are triage signals, not vulnerability claims. High scores mean the driver resembles known risky BYOVD classes and deserves manual review in IDA.",
        "Priority is the field used for ordering. It favors local vulnerable/suspect references and penalizes noisy core Windows drivers, missing user surfaces, and mitigation signals.",
        "Confidence increases when multiple independent risky families and an apparent user-reachable surface are present.",
        "Confidence decreases when mitigation signals are present or when a broad core Windows driver has no obvious exposed test surface in this offline scan.",
        "The main manual-review targets are device ACLs, IOCTL access requirements, caller-controlled physical/MSR/register parameters, registry writes, user pointer validation, object namespaces, WMI/ALPC ports, and lifetime/cancel paths."
    ]
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=".", help="Workspace root")
    parser.add_argument("--out-dir", default="reports", help="Output report directory")
    parser.add_argument("--dirs", nargs="*", default=DEFAULT_DIRS, help="Driver directories")
    args = parser.parse_args()

    root = Path(args.root).resolve()
    out_dir = (root / args.out_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    rows: list[dict[str, Any]] = []
    for dirname in args.dirs:
        folder = root / dirname
        if not folder.exists():
            continue
        for path in sorted(folder.rglob("*")):
            if path.is_file() and path.suffix.lower() in {".sys", ".dll", ".exe", ".bin", ".dat"}:
                try:
                    rows.append(scan_file(path, root))
                except Exception as exc:
                    rows.append({
                        "folder": str(path.parent.relative_to(root)),
                        "file": path.name,
                        "path": str(path),
                        "error": str(exc),
                        "risk_score": 0,
                        "review_priority": 0,
                        "confidence": 0,
                        "false_positive_risk": "Unknown",
                        "risk_reasons": [],
                        "mitigations": [],
                        "triage_notes": [str(exc)],
                        "families": []
                    })

    json_path = out_dir / "dragon_reverse_corpus_audit.json"
    md_path = out_dir / "dragon_reverse_corpus_audit.md"
    json_path.write_text(json.dumps({"root": str(root), "count": len(rows), "drivers": rows}, indent=2), encoding="utf-8")
    md_path.write_text(markdown_report(rows, root), encoding="utf-8")
    print("Wrote %s" % json_path)
    print("Wrote %s" % md_path)
    print("Scanned %d files" % len(rows))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
