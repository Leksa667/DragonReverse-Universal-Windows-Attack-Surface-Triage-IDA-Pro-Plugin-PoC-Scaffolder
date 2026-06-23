# Dragon Reverse for IDA Pro 9.2+
#
# Static triage and correlation plugin for authorized Windows driver research.
# The plugin identifies risky primitives and similarity to known BYOVD classes.
# It intentionally does not generate payloads, exploit code, or runtime PoCs.

from __future__ import annotations

import hashlib
import json
import os
import re
import traceback
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable

import ida_auto
import ida_bytes
import ida_funcs
import ida_hexrays
import ida_idaapi
import ida_kernwin
import ida_lines
import ida_name
import ida_nalt
import ida_ua
import idautils
import idc

from PySide6 import QtCore, QtGui, QtWidgets

try:
    import dragon_reverse_logic as dr_logic
except Exception:
    dr_logic = None


PLUGIN_TITLE = "Dragon Reverse"
ACTION_OPEN = "dragon_reverse:open"
ACTION_SHORTCUT = "Ctrl+Shift+D"
RULES_FILE = "dragon_reverse_rules.json"

ANALYSIS_MODES = [
    ("auto", "Auto"),
    ("driver", "Driver"),
    ("service", "Service"),
    ("hypervisor", "Hypervisor"),
    ("universal", "Universal"),
]

try:
    USER_ROLE = QtCore.Qt.UserRole
except AttributeError:
    USER_ROLE = QtCore.Qt.ItemDataRole.UserRole


DEFAULT_RULES = {
    "schema_version": 1,
    "known_hashes": {},
    "lol_drivers": {
        "api_json": "https://www.loldrivers.io/api/drivers.json",
        "site": "https://www.loldrivers.io/",
        "github": "https://github.com/magicsword-io/LOLDrivers"
    },
    "families": [
        {
            "id": "physmem_map",
            "name": "Physical memory mapping primitive",
            "signals": ["MmMapIoSpace", "MmMapIoSpaceEx", "MmMapLockedPagesSpecifyCache", "MmGetPhysicalAddress"],
            "min_hits": 1,
            "negative_signals": ["IoValidateDeviceIoControlAccess", "SeSinglePrivilegeCheck", "SePrivilegeCheck"],
            "score": 22,
            "review": "Trace callers from IOCTL dispatchers to mapping APIs and verify range validation plus privilege gates."
        },
        {
            "id": "msr_control",
            "name": "MSR programming primitive",
            "signals": ["wrmsr", "rdmsr", "__writemsr", "__readmsr"],
            "min_hits": 1,
            "negative_signals": ["SeSinglePrivilegeCheck", "IoValidateDeviceIoControlAccess"],
            "score": 24,
            "review": "Verify MSR indexes, value masks, session ownership, and caller authorization."
        },
        {
            "id": "registry_service_write",
            "name": "Privileged service-key registry write",
            "signals": ["ZwOpenKey", "ZwCreateKey", "ZwSetValueKey", "RtlWriteRegistryValue", "CurrentControlSet\\\\Services"],
            "min_hits": 1,
            "negative_signals": ["SeSinglePrivilegeCheck", "IoValidateDeviceIoControlAccess"],
            "score": 18,
            "review": "Check whether a low-privileged device handle can cause privileged registry writes."
        },
        {
            "id": "weak_device_acl",
            "name": "Weak device object exposure",
            "signals": ["IoCreateDevice", "IoCreateSymbolicLink", "\\\\DosDevices\\\\", "\\\\Device\\\\"],
            "min_hits": 1,
            "negative_signals": ["IoCreateDeviceSecure", "IoValidateDeviceIoControlAccess"],
            "score": 14,
            "review": "Recover the SDDL/default DACL and verify open rights required for each IOCTL."
        },
        {
            "id": "method_neither_user_pointer",
            "name": "METHOD_NEITHER or user-pointer trust",
            "signals": ["METHOD_NEITHER", "Type3InputBuffer", "UserBuffer", "ProbeForRead", "ProbeForWrite", "memcpy", "memmove"],
            "min_hits": 1,
            "negative_signals": ["ProbeForRead", "ProbeForWrite", "__try"],
            "score": 18,
            "review": "Inspect pointer provenance, try/except guards, IOCTL method, lengths, and caller mode."
        },
        {
            "id": "kernel_memory_rw",
            "name": "Kernel memory read/write primitive",
            "signals": ["MmCopyVirtualMemory", "MmCopyMemory", "ZwMapViewOfSection", "IoAllocateMdl", "MmProbeAndLockPages", "PsLookupProcessByProcessId", "ObReferenceObjectByHandle"],
            "min_hits": 1,
            "negative_signals": ["SeSinglePrivilegeCheck", "IoValidateDeviceIoControlAccess"],
            "score": 20,
            "review": "Trace whether process, section, MDL, source, or destination parameters are caller-controlled."
        }
    ]
}


SEVERITY_ORDER = {"Critical": 5, "High": 4, "Medium": 3, "Low": 2, "Info": 1}

SEVERITY_COLORS = {
    "Critical": {"fg": "#ffffff", "bg": "#b42318", "soft": "#fde7e7", "border": "#f04438"},
    "High": {"fg": "#ffffff", "bg": "#c2410c", "soft": "#ffead5", "border": "#fb923c"},
    "Medium": {"fg": "#1f2937", "bg": "#f59e0b", "soft": "#fef3c7", "border": "#fbbf24"},
    "Low": {"fg": "#ffffff", "bg": "#2563eb", "soft": "#dbeafe", "border": "#60a5fa"},
    "Info": {"fg": "#ffffff", "bg": "#64748b", "soft": "#e2e8f0", "border": "#94a3b8"}
}

COMMON_CUSTOM_IOCTL_DEVICE_TYPES = {0x22}
NON_DISPATCHER_FUNCTION_NAMES = {
    "memcpy", "memmove", "memset", "memcmp",
    "strcpy", "strncpy", "sprintf", "swprintf",
    "dbgprint", "dbgprintex",
    "__security_check_cookie", "_security_check_cookie",
    "__report_gsfailure", "__chkstk", "__chkstk_ms"
}

SENSITIVE_REACHABILITY_FAMILIES = {
    "physmem_map", "msr_control", "port_io", "registry_service_write",
    "kernel_memory_rw", "mdl_dma_surface", "process_token_sensitive",
    "process_kill",
    "security_descriptor_write", "callback_or_filter_tamper",
    "firmware_pci_config", "physical_section_object", "firmware_environment",
    "legacy_dma_adapter", "system_information_write", "minifilter_user_comm",
    "impersonation_boundary", "kernel_patch_or_exec_mapping",
    "wmi_etw_control_plane", "alpc_port_boundary",
    "rpc_interface_surface", "named_pipe_surface", "com_dcom_surface",
    "hypercall_surface", "vmbus_packet_surface", "privileged_file_op",
    "toctou_user_buffer"
}

SENSITIVE_REACHABILITY_ROLES = {
    "Physical memory mapper", "MSR control path", "Port/MMIO access path",
    "MDL/DMA boundary", "Process/token object path",
    "Process termination / protection bypass",
    "Registry/service-key writer", "Security descriptor / ACL writer",
    "Firmware/PCI/bus access", "Minifilter communication port",
    "Impersonation boundary", "WMI/ETW control plane",
    "ALPC/named port boundary", "Executable mapping / patch surface",
    "RPC interface surface", "Named pipe IPC surface",
    "COM/DCOM activation surface", "Hypervisor hypercall surface",
    "VMBus packet parser", "Privileged file/symlink operation",
    "TOCTOU user-buffer race candidate"
}

ENTRY_SURFACE_ROLES = {
    "IOCTL dispatcher", "Device ACL / namespace exposure",
    "RPC interface surface", "Named pipe IPC surface", "COM/DCOM activation surface",
    "ALPC/named port boundary", "Hypervisor hypercall surface", "VMBus packet parser"
}

IOCTL_METHODS = {
    0: "METHOD_BUFFERED",
    1: "METHOD_IN_DIRECT",
    2: "METHOD_OUT_DIRECT",
    3: "METHOD_NEITHER"
}

IOCTL_ACCESS = {
    0: "FILE_ANY_ACCESS",
    1: "FILE_READ_ACCESS",
    2: "FILE_WRITE_ACCESS",
    3: "FILE_READ_WRITE_ACCESS"
}

INSTRUCTION_SIGNALS = {
    "wrmsr": "MSR write instruction",
    "rdmsr": "MSR read instruction",
    "in": "port input instruction",
    "out": "port output instruction",
    "ins": "port string input instruction",
    "outs": "port string output instruction",
    "vmcall": "Intel hypercall instruction",
    "vmmcall": "AMD hypercall instruction",
    "cli": "interrupt control instruction",
    "sti": "interrupt control instruction"
}

CRITICAL_STRINGS = [
    "\\\\Device\\\\",
    "\\\\DosDevices\\\\",
    "\\\\BaseNamedObjects\\\\",
    "\\\\GLOBAL??\\\\",
    "\\\\RPC Control\\\\",
    "CurrentControlSet\\\\Services",
    "Registry\\\\Machine\\\\System",
    "\\\\Device\\\\PhysicalMemory",
    "METHOD_NEITHER",
    "FILE_ANY_ACCESS",
    "Type3InputBuffer",
    "UserBuffer",
    "SystemBuffer",
    "IoControlCode",
    "SeDebugPrivilege",
    "SeSystemEnvironmentPrivilege",
    "PAGE_EXECUTE_READWRITE",
    "ALPC_PORT_ATTRIBUTES",
    "SECURITY_CLIENT_CONTEXT",
    "RpcServerRegisterIf",
    "RpcServerRegisterIfEx",
    "RpcServerUseProtseqEp",
    "NdrServerCall2",
    "\\\\pipe\\\\",
    "\\\\.\\\\pipe\\\\",
    "CreateNamedPipe",
    "CoRegisterClassObject",
    "CoInitializeSecurity",
    "CLSID",
    "AppID",
    "HvlInvokeHypercall",
    "VMBus",
    "VmbChannel",
    "SetSecurityInfo",
    "SetNamedSecurityInfo",
    "MoveFileEx",
    "CreateHardLink",
    "CreateSymbolicLink",
    "ImpersonateNamedPipeClient",
    "RpcImpersonateClient",
    "CoImpersonateClient"
]

PSEUDOCODE_TOKENS = [
    "IoControlCode", "SystemBuffer", "Type3InputBuffer", "UserBuffer",
    "InputBufferLength", "OutputBufferLength", "Parameters.DeviceIoControl",
    "IRP_MJ_DEVICE_CONTROL", "MajorFunction", "CurrentStackLocation",
    "MmMapIoSpace", "MmMapIoSpaceEx", "MmMapLockedPagesSpecifyCache",
    "MmMapViewInSystemSpace", "MmCopyVirtualMemory", "MmCopyMemory",
    "ZwMapViewOfSection", "ZwOpenSection", "ZwCreateSection",
    "ZwSetValueKey", "RtlWriteRegistryValue", "wrmsr", "rdmsr",
    "__writemsr", "__readmsr", "memcpy", "memmove", "RtlCopyMemory",
    "ProbeForRead", "ProbeForWrite", "PreviousMode", "RequestorMode",
    "IoValidateDeviceIoControlAccess", "SeSinglePrivilegeCheck", "SePrivilegeCheck",
    "PsLookupProcessByProcessId", "PsReferencePrimaryToken", "PsReferenceImpersonationToken",
    "ObReferenceObjectByHandle", "ZwTerminateProcess", "PsTerminateSystemThread",
    "TerminateProcess", "ZwSetSecurityObject", "RtlSetDaclSecurityDescriptor",
    "FltCreateCommunicationPort", "IoGetDmaAdapter", "MapTransfer",
    "ExSetFirmwareEnvironmentVariable", "ZwSetSystemInformation", "ZwSystemDebugControl",
    "IoSetCancelRoutine", "IoAcquireCancelSpinLock", "ExQueueWorkItem",
    "IoWMIRegistrationControl", "WmiSystemControl", "ZwAlpcCreatePort",
    "ZwAlpcSendWaitReceivePort", "PAGE_EXECUTE_READWRITE", "\\Device\\PhysicalMemory",
    "RpcServerRegisterIf", "RpcServerRegisterIfEx", "RpcServerUseProtseqEp",
    "NdrServerCall2", "MIDL_SERVER_INFO", "RPC_SERVER_INTERFACE",
    "CreateNamedPipe", "ConnectNamedPipe", "ImpersonateNamedPipeClient",
    "\\\\.\\pipe\\", "\\pipe\\", "CoRegisterClassObject", "CoInitializeSecurity",
    "CoCreateInstance", "CLSIDFromString", "CLSID", "AppID",
    "HvlInvokeHypercall", "HvCall", "VMBus", "VmbChannel", "RingBuffer",
    "SetSecurityInfo", "SetNamedSecurityInfo", "MoveFileEx", "CreateHardLink",
    "CreateSymbolicLink", "ReplaceFile", "DeleteFile", "RpcImpersonateClient",
    "CoImpersonateClient", "RevertToSelf", "OpenThreadToken", "DuplicateTokenEx"
]

PSEUDOCODE_FACT_GROUPS = {
    "ioctl_surface": [
        "IoControlCode", "Parameters.DeviceIoControl", "IRP_MJ_DEVICE_CONTROL",
        "MajorFunction[14]", "MajorFunction[0xE]", "CurrentStackLocation"
    ],
    "user_buffers": [
        "SystemBuffer", "Type3InputBuffer", "UserBuffer", "MdlAddress",
        "AssociatedIrp.SystemBuffer", "Irp->UserBuffer"
    ],
    "length_fields": [
        "InputBufferLength", "OutputBufferLength",
        "Parameters.DeviceIoControl.InputBufferLength",
        "Parameters.DeviceIoControl.OutputBufferLength"
    ],
    "guards": [
        "ProbeForRead", "ProbeForWrite", "__try", "IoValidateDeviceIoControlAccess",
        "SeSinglePrivilegeCheck", "SePrivilegeCheck", "ExGetPreviousMode",
        "PreviousMode", "RequestorMode", "SeAccessCheck"
    ],
    "memory_sinks": [
        "MmMapIoSpace", "MmMapIoSpaceEx", "MmMapLockedPagesSpecifyCache",
        "MmGetPhysicalAddress", "MmCopyVirtualMemory", "MmCopyMemory",
        "ZwMapViewOfSection", "ZwOpenSection", "ZwCreateSection",
        "IoAllocateMdl", "MmProbeAndLockPages", "MmBuildMdlForNonPagedPool"
    ],
    "copy_sinks": ["memcpy", "memmove", "RtlCopyMemory", "RtlMoveMemory"],
    "port_sinks": ["READ_PORT", "WRITE_PORT", "READ_REGISTER", "WRITE_REGISTER", "__inbyte", "__outbyte", "inp", "outp"],
    "registry_sinks": ["ZwCreateKey", "ZwSetValueKey", "RtlWriteRegistryValue"],
    "registry_open": ["ZwOpenKey", "CurrentControlSet\\Services", "Registry\\Machine\\System"],
    "token_sinks": ["PsLookupProcessByProcessId", "PsReferencePrimaryToken", "PsReferenceImpersonationToken", "ObReferenceObjectByHandle", "ZwOpenProcess"],
    "process_kill_sinks": ["ZwTerminateProcess", "TerminateProcess", "PsTerminateSystemThread"],
    "firmware_sinks": ["ExSetFirmwareEnvironmentVariable", "ZwSetSystemEnvironmentValue", "HalSetBusData", "HalSetBusDataByOffset"],
    "exec_sinks": ["MmProtectMdlSystemAddress", "ZwProtectVirtualMemory", "PAGE_EXECUTE_READWRITE", "PsInitialSystemProcess"],
    "rpc_surface": ["RpcServerRegisterIf", "RpcServerRegisterIfEx", "RpcServerUseProtseqEp", "NdrServerCall2", "MIDL_SERVER_INFO", "RPC_SERVER_INTERFACE"],
    "named_pipe_surface": ["CreateNamedPipe", "ConnectNamedPipe", "ImpersonateNamedPipeClient", "\\\\.\\pipe\\", "\\pipe\\"],
    "com_surface": ["CoRegisterClassObject", "CoInitializeSecurity", "CoCreateInstance", "CLSIDFromString", "CLSID", "AppID", "DCOM"],
    "alpc_surface": ["ZwAlpcCreatePort", "ZwAlpcConnectPort", "ZwAlpcSendWaitReceivePort", "ALPC_PORT_ATTRIBUTES", "\\RPC Control\\"],
    "impersonation_sinks": ["RpcImpersonateClient", "CoImpersonateClient", "ImpersonateNamedPipeClient", "SeImpersonateClient", "RevertToSelf", "OpenThreadToken", "DuplicateTokenEx"],
    "file_sinks": ["SetSecurityInfo", "SetNamedSecurityInfo", "MoveFileEx", "CreateHardLink", "CreateSymbolicLink", "ReplaceFile", "DeleteFile", "CopyFile", "CreateFile"],
    "hypercall_sinks": ["vmcall", "vmmcall", "HvlInvokeHypercall", "HvCall", "WHvRunVirtualProcessor", "WHvCall"],
    "vmbus_surface": ["VMBus", "VmbChannel", "VmbPacket", "RingBuffer", "VmbChannelPacket", "HvPostMessage"]
}

CALLER_MODE_GUARD_TOKENS = {
    "ExGetPreviousMode", "PreviousMode", "RequestorMode",
    "Irp->RequestorMode", "KPROCESSOR_MODE", "UserMode", "KernelMode"
}

PSEUDOCODE_SENSITIVE_GROUPS = {
    "memory_sinks", "port_sinks", "registry_sinks", "token_sinks",
    "process_kill_sinks", "firmware_sinks", "exec_sinks",
    "rpc_surface", "named_pipe_surface", "com_surface", "alpc_surface",
    "impersonation_sinks", "file_sinks", "hypercall_sinks", "vmbus_surface"
}

TRIAGE_GUARDRAILS = [
    "chain_type=pseudocode means a very plausible static path, not final proof.",
    "no-nearby-guard-in-pseudocode-window means no guard token was seen close to the sink in decompiled text; it does not prove no validation exists.",
    "Scores and confidence values are triage priorities, not bounty confirmations.",
    "A reportable claim still needs dynamic reachability, authorization context, and a deterministic or reversible proof."
]

BOUNTY_PROOF_ORDER = [
    "Exact driver hash, version, signer, Authenticode status, file ACL, and service state.",
    "Low-privileged CreateFile matrix for the device path.",
    "Static dispatcher assignment from DriverEntry/device setup to IRP_MJ_DEVICE_CONTROL.",
    "IOCTL access/method evidence, especially FILE_ANY_ACCESS and METHOD_NEITHER.",
    "Per-IOCTL static link from input fields to sensitive sinks such as MmMapIoSpace, MmMapLockedPagesSpecifyCache, IoAllocateMdl, and port I/O."
]

PROOF_SINK_TOKENS = {
    "MmMapIoSpace", "MmMapIoSpaceEx", "MmMapLockedPagesSpecifyCache",
    "IoAllocateMdl", "MmBuildMdlForNonPagedPool", "MmGetPhysicalAddress",
    "__inbyte", "__outbyte", "inp", "outp", "READ_PORT", "WRITE_PORT",
    "READ_REGISTER", "WRITE_REGISTER", "in", "out",
    "RpcServerRegisterIf", "RpcServerRegisterIfEx", "NdrServerCall2",
    "CreateNamedPipe", "CoRegisterClassObject", "ZwAlpcCreatePort",
    "RpcImpersonateClient", "CoImpersonateClient", "ImpersonateNamedPipeClient",
    "SetSecurityInfo", "SetNamedSecurityInfo", "MoveFileEx",
    "vmcall", "vmmcall", "HvlInvokeHypercall", "VMBus", "VmbChannel"
}

PSEUDOCODE_TYPE_SIZES = {
    "_BYTE": 1,
    "BYTE": 1,
    "char": 1,
    "_WORD": 2,
    "WORD": 2,
    "short": 2,
    "_DWORD": 4,
    "DWORD": 4,
    "int": 4,
    "ULONG": 4,
    "_QWORD": 8,
    "QWORD": 8,
    "__int64": 8,
    "UINT64": 8,
    "ULONG64": 8,
    "PVOID": 8,
    "PHYSICAL_ADDRESS": 8,
}

CTL_CODE_TOKEN_VALUES = {
    "FILE_DEVICE_UNKNOWN": 0x22,
    "METHOD_BUFFERED": 0,
    "METHOD_IN_DIRECT": 1,
    "METHOD_OUT_DIRECT": 2,
    "METHOD_NEITHER": 3,
    "FILE_ANY_ACCESS": 0,
    "FILE_READ_ACCESS": 1,
    "FILE_WRITE_ACCESS": 2,
    "FILE_READ_WRITE_ACCESS": 3,
}

COPY_ONLY_TOKENS = {"memcpy", "memmove", "RtlCopyMemory", "RtlMoveMemory", "memset"}
REGISTRY_WRITE_TOKENS = {"ZwCreateKey", "ZwSetValueKey", "RtlWriteRegistryValue"}
USER_POINTER_TOKENS = {
    "METHOD_NEITHER", "Type3InputBuffer", "UserBuffer", "SystemBuffer",
    "InputBufferLength", "OutputBufferLength", "Parameters.DeviceIoControl"
}

ROLE_RULES = [
    ("Driver entry / device setup", ["DriverEntry", "IoCreateDevice", "IoCreateDeviceSecure", "IoCreateSymbolicLink", "IoRegisterDeviceInterface"]),
    ("IOCTL dispatcher", ["IRP_MJ_DEVICE_CONTROL", "IoControlCode", "Parameters.DeviceIoControl", "SystemBuffer", "Type3InputBuffer", "UserBuffer", "FILE_ANY_ACCESS", "METHOD_NEITHER"]),
    ("Device ACL / namespace exposure", ["IoCreateDevice", "IoCreateDeviceSecure", "IoCreateSymbolicLink", "\\DosDevices\\", "\\Device\\", "\\GLOBAL??\\"]),
    ("Registry/service-key writer", ["ZwSetValueKey", "RtlWriteRegistryValue", "CurrentControlSet\\Services", "Registry\\Machine\\System"]),
    ("Physical memory mapper", ["MmMapIoSpace", "MmMapIoSpaceEx", "MmMapLockedPagesSpecifyCache", "MmGetPhysicalAddress", "\\Device\\PhysicalMemory"]),
    ("MSR control path", ["wrmsr", "rdmsr", "__writemsr", "__readmsr"]),
    ("Port/MMIO access path", ["READ_PORT", "WRITE_PORT", "READ_REGISTER", "WRITE_REGISTER", "in", "out"]),
    ("MDL/DMA boundary", ["IoAllocateMdl", "MmProbeAndLockPages", "MmBuildMdlForNonPagedPool", "IoGetDmaAdapter", "MapTransfer", "GetScatterGatherList"]),
    ("Process/token object path", ["PsLookupProcessByProcessId", "PsReferencePrimaryToken", "PsReferenceImpersonationToken", "ZwOpenProcess", "ObReferenceObjectByHandle"]),
    ("Process termination / protection bypass", ["ZwTerminateProcess", "TerminateProcess", "PsTerminateSystemThread", "PROCESS_TERMINATE"]),
    ("Security descriptor / ACL writer", ["ZwSetSecurityObject", "RtlSetDaclSecurityDescriptor", "RtlAddAccessAllowedAce", "SeAssignSecurity"]),
    ("Callback/filter control", ["PsSetCreateProcessNotifyRoutine", "ObRegisterCallbacks", "CmRegisterCallback", "FltRegisterFilter", "FltStartFiltering"]),
    ("Firmware/PCI/bus access", ["ExSetFirmwareEnvironmentVariable", "ZwSetSystemEnvironmentValue", "HalSetBusData", "IRP_MN_WRITE_CONFIG", "SMBIOS", "ACPI", "PCI"]),
    ("Minifilter communication port", ["FltCreateCommunicationPort", "FltSendMessage", "FltGetMessage", "FltReplyMessage"]),
    ("IRP lifetime/race path", ["IoSetCancelRoutine", "IoCancelIrp", "IoAcquireCancelSpinLock", "IoInitializeRemoveLock", "ExQueueWorkItem"]),
    ("Impersonation boundary", ["SeImpersonateClient", "PsImpersonateClient", "SeCreateClientSecurity", "SECURITY_CLIENT_CONTEXT"]),
    ("WMI/ETW control plane", ["IoWMIRegistrationControl", "WmiSystemControl", "EtwRegister", "EtwWrite", "TraceLoggingWrite"]),
    ("ALPC/named port boundary", ["ZwAlpcCreatePort", "ZwAlpcConnectPort", "ZwAlpcSendWaitReceivePort", "ALPC_PORT_ATTRIBUTES"]),
    ("Executable mapping / patch surface", ["MmGetSystemRoutineAddress", "MmProtectMdlSystemAddress", "ZwProtectVirtualMemory", "PAGE_EXECUTE_READWRITE", "PsInitialSystemProcess"]),
    ("RPC interface surface", ["RpcServerRegisterIf", "RpcServerRegisterIfEx", "RpcServerUseProtseqEp", "NdrServerCall2", "MIDL_SERVER_INFO", "RPC_SERVER_INTERFACE"]),
    ("Named pipe IPC surface", ["CreateNamedPipe", "ConnectNamedPipe", "ImpersonateNamedPipeClient", "\\\\.\\pipe\\", "\\pipe\\"]),
    ("COM/DCOM activation surface", ["CoRegisterClassObject", "CoInitializeSecurity", "CoCreateInstance", "CLSIDFromString", "CLSID", "AppID"]),
    ("Hypervisor hypercall surface", ["vmcall", "vmmcall", "HvlInvokeHypercall", "HvCall", "WHvRunVirtualProcessor"]),
    ("VMBus packet parser", ["VMBus", "VmbChannel", "VmbPacket", "RingBuffer", "HvPostMessage"]),
    ("Privileged file/symlink operation", ["SetSecurityInfo", "SetNamedSecurityInfo", "MoveFileEx", "CreateHardLink", "CreateSymbolicLink", "ReplaceFile"]),
    ("TOCTOU user-buffer race candidate", ["toctou-user-buffer-reread", "SystemBuffer", "Type3InputBuffer", "UserBuffer"])
]

V5_FAMILY_RULES = [
    {
        "id": "rpc_interface_surface",
        "name": "RPC interface surface",
        "description": "Service exposes RPC interfaces that should be mapped to UUIDs/opnums and caller authorization.",
        "signals": ["RpcServerRegisterIf", "RpcServerRegisterIfEx", "RpcServerUseProtseqEp", "NdrServerCall2", "MIDL_SERVER_INFO", "RPC_SERVER_INTERFACE"],
        "min_hits": 1,
        "negative_signals": ["RpcServerRegisterIfEx", "RPC_IF_ALLOW_SECURE_ONLY", "RpcMgmtSetAuthorizationFn", "RpcImpersonateClient"],
        "score": 20,
        "modes": ["service", "universal"],
        "review": "Extract interface UUIDs, endpoints, protocol sequences, security callback, opnums, and impersonation/authorization behavior. Map with RpcView or IDA xrefs."
    },
    {
        "id": "named_pipe_surface",
        "name": "Named pipe IPC surface",
        "description": "Service creates named pipes or pipe endpoints that may be writable by low-privileged users.",
        "signals": ["CreateNamedPipe", "ConnectNamedPipe", "ImpersonateNamedPipeClient", "\\\\.\\pipe\\", "\\pipe\\"],
        "min_hits": 1,
        "negative_signals": ["ConvertStringSecurityDescriptorToSecurityDescriptor", "SetSecurityInfo", "InitializeSecurityDescriptor", "ImpersonateNamedPipeClient"],
        "score": 18,
        "modes": ["service", "universal"],
        "review": "Recover pipe name and security descriptor. Verify low-privileged write/connect rights and whether the service trusts pipe messages."
    },
    {
        "id": "com_dcom_surface",
        "name": "COM/DCOM activation surface",
        "description": "Service or broker exposes COM/DCOM class objects or weak COM security configuration.",
        "signals": ["CoRegisterClassObject", "CoInitializeSecurity", "CoCreateInstance", "CLSIDFromString", "CLSID", "AppID"],
        "min_hits": 1,
        "negative_signals": ["RPC_C_AUTHN_LEVEL_PKT_PRIVACY", "RPC_C_IMP_LEVEL_IDENTIFY", "EOAC_DISABLE_AAA"],
        "score": 18,
        "modes": ["service", "universal"],
        "review": "Recover CLSID/AppID, launch/access permissions, authentication level, impersonation level, and brokered privileged actions."
    },
    {
        "id": "alpc_service_surface",
        "name": "ALPC or named port service surface",
        "description": "Service exposes ALPC/named port IPC where message parsing and security context matter.",
        "signals": ["ZwAlpcCreatePort", "ZwAlpcConnectPort", "ZwAlpcSendWaitReceivePort", "ALPC_PORT_ATTRIBUTES", "\\\\RPC Control\\\\"],
        "min_hits": 1,
        "negative_signals": ["SeAccessCheck", "Impersonate", "SecurityQos"],
        "score": 18,
        "modes": ["service", "driver", "universal"],
        "review": "Recover port name, security descriptor, message struct, impersonation/security QoS, and server-side authorization."
    },
    {
        "id": "impersonation_boundary",
        "name": "Impersonation boundary",
        "description": "Service impersonates clients or handles tokens; missing level checks often become SYSTEM LPE.",
        "signals": ["RpcImpersonateClient", "CoImpersonateClient", "ImpersonateNamedPipeClient", "SeImpersonateClient", "OpenThreadToken", "DuplicateTokenEx", "RevertToSelf"],
        "min_hits": 1,
        "negative_signals": ["SecurityImpersonation", "SecurityDelegation", "RpcRevertToSelf", "RevertToSelf", "TokenImpersonationLevel"],
        "score": 22,
        "modes": ["service", "universal"],
        "review": "Verify impersonation level, token type, client identity checks, RevertToSelf on every path, and privileged action after impersonation."
    },
    {
        "id": "privileged_file_op",
        "name": "Privileged file or symlink operation",
        "description": "SYSTEM service performs file move/copy/delete/ACL operations that may be redirectable with links or races.",
        "signals": ["SetSecurityInfo", "SetNamedSecurityInfo", "MoveFileEx", "CreateHardLink", "CreateSymbolicLink", "ReplaceFile", "DeleteFile", "CopyFile"],
        "min_hits": 1,
        "negative_signals": ["GetFinalPathNameByHandle", "FILE_FLAG_OPEN_REPARSE_POINT", "SetFileInformationByHandle", "SeSinglePrivilegeCheck"],
        "score": 20,
        "modes": ["service", "universal"],
        "review": "Trace caller-controlled paths into privileged file operations. Check reparse points, hardlinks, final path validation, ACL changes, and direct-denial controls."
    },
    {
        "id": "hypercall_surface",
        "name": "Hypervisor hypercall surface",
        "description": "Binary contains hypercall instructions or Hyper-V/WHVP invocation paths.",
        "signals": ["vmcall", "vmmcall", "HvlInvokeHypercall", "HvCall", "WHvRunVirtualProcessor", "WHvCall"],
        "min_hits": 1,
        "negative_signals": ["HvGetPartitionId", "WHvGetCapability"],
        "score": 24,
        "modes": ["hypervisor", "universal"],
        "review": "Map hypercall numbers, guest-controlled registers/buffers, partition/VP context, privilege checks, and expected input struct sizes."
    },
    {
        "id": "vmbus_packet_surface",
        "name": "VMBus or virtual device packet parser",
        "description": "Virtualization component parses guest/host packets, ring buffers, or VMBus channels.",
        "signals": ["VMBus", "VmbChannel", "VmbPacket", "RingBuffer", "HvPostMessage", "VmbChannelPacket"],
        "min_hits": 1,
        "negative_signals": ["RtlULongAdd", "RtlSizeTAdd", "RtlULongLongAdd", "ProbeForRead"],
        "score": 22,
        "modes": ["hypervisor", "universal"],
        "review": "Recover packet headers, length arithmetic, ring-buffer bounds, message type dispatch, and guest-controlled fields."
    },
    {
        "id": "toctou_user_buffer",
        "name": "TOCTOU user-buffer reread",
        "description": "User-controlled buffer or pointer appears to be checked and read again later, suggesting raceable validation.",
        "signals": ["toctou-user-buffer-reread", "SystemBuffer", "Type3InputBuffer", "UserBuffer", "InputBufferLength"],
        "min_hits": 1,
        "negative_signals": ["local-copy-before-check", "ProbeForRead", "__try"],
        "score": 24,
        "modes": ["driver", "service", "hypervisor", "universal"],
        "review": "Confirm whether the same user-controlled field is validated, then dereferenced/read again from the original source instead of a captured local copy."
    }
]


@dataclass
class Finding:
    severity: str
    score: int
    ea: int
    function: str
    category: str
    signal: str
    evidence: str
    review: str
    family: str = ""
    confidence_reason: str = ""
    review_status: str = "needs proof"

    def as_row(self) -> list[str]:
        return [
            self.severity,
            str(self.score),
            self.review_status,
            ea_text(self.ea),
            self.function,
            self.category,
            self.signal,
            self.evidence,
            self.confidence_reason
        ]


@dataclass
class FunctionSummary:
    ea: int
    name: str
    score: int = 0
    roles: set[str] = field(default_factory=set)
    families: set[str] = field(default_factory=set)
    calls: set[str] = field(default_factory=set)
    callers: set[str] = field(default_factory=set)
    callees: set[str] = field(default_factory=set)
    mnemonics: set[str] = field(default_factory=set)
    strings: set[str] = field(default_factory=set)
    ioctls: list[dict[str, Any]] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    pseudocode_hits: list[str] = field(default_factory=list)
    pseudocode_facts: dict[str, list[str]] = field(default_factory=dict)
    proof_notes: list[str] = field(default_factory=list)
    confidence_reason: str = ""
    review_status: str = "needs proof"


@dataclass
class PrimitiveChain:
    severity: str
    confidence: int
    entry: str
    entry_ea: int
    target: str
    target_ea: int
    primitive: str
    access_surface: str
    evidence: str
    proof_focus: str
    chain_type: str = "strict"
    confidence_reason: str = ""
    review_status: str = "needs proof"

    def as_row(self) -> list[str]:
        return [
            self.severity,
            str(self.confidence),
            self.chain_type,
            self.review_status,
            ea_text(self.entry_ea),
            self.entry,
            ea_text(self.target_ea),
            self.target,
            self.primitive,
            self.access_surface,
            self.evidence,
            self.confidence_reason
        ]


def ea_text(ea: int) -> str:
    if ea is None or ea == idc.BADADDR or ea < 0:
        return ""
    return "0x%X" % ea


def safe_tag_remove(text: Any) -> str:
    try:
        return ida_lines.tag_remove(str(text))
    except Exception:
        return str(text)


def safe_name(ea: int) -> str:
    if ea is None or ea == idc.BADADDR or ea < 0:
        return ""
    try:
        name = ida_name.get_name(ea)
        if name:
            return name
    except Exception:
        pass
    try:
        return idc.get_name(ea) or ""
    except Exception:
        return ""


def qt_ea_data(ea: int) -> int:
    try:
        value = int(ea)
    except Exception:
        return -1
    if value < 0 or value == idc.BADADDR or value > 0x7FFFFFFFFFFFFFFF:
        return -1
    return value


def severity_from_score(score: int) -> str:
    if dr_logic is not None:
        return dr_logic.severity_from_score(score)
    if score >= 55:
        return "Critical"
    if score >= 35:
        return "High"
    if score >= 18:
        return "Medium"
    if score >= 8:
        return "Low"
    return "Info"


def decode_ioctl(value: int) -> dict[str, Any] | None:
    if dr_logic is not None:
        return dr_logic.decode_ioctl_value(value)
    if value is None or value <= 0 or value > 0xFFFFFFFF:
        return None
    method = value & 0x3
    function = (value >> 2) & 0xFFF
    access = (value >> 14) & 0x3
    device_type = (value >> 16) & 0xFFFF
    # Real CTL_CODE values should carry a device type. Requiring either
    # FILE_DEVICE_UNKNOWN or vendor-defined device types removes most code
    # addresses, offsets, hashes, and magic constants from the candidate list.
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
        "confidence": confidence
    }


def load_rules() -> dict[str, Any]:
    plugin_dir = os.path.dirname(os.path.abspath(__file__))
    path = os.path.join(plugin_dir, RULES_FILE)
    rules = None
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                rules = json.load(f)
            if not isinstance(rules, dict):
                rules = None
        except Exception:
            ida_kernwin.msg("[DragonReverse] Failed to load %s\n%s\n" % (path, traceback.format_exc()))
    if rules is None:
        rules = dict(DEFAULT_RULES)
    return augment_rules_with_v5(rules)


def augment_rules_with_v5(rules: dict[str, Any]) -> dict[str, Any]:
    out = dict(rules)
    families = list(out.get("families", []) or [])
    seen = {str(family.get("id", "")).lower() for family in families if isinstance(family, dict)}
    for family in V5_FAMILY_RULES:
        if family["id"].lower() not in seen:
            families.append(dict(family))
            seen.add(family["id"].lower())
    out["families"] = families
    notes = list(out.get("source_notes", []) or [])
    note = "V5 universal attack-surface rules are injected at runtime: services, RPC/ALPC, named pipes, COM/DCOM, hypercalls, VMBus, TOCTOU, impersonation, and privileged file operations."
    if note not in notes:
        notes.append(note)
    out["source_notes"] = notes
    return out


def input_sha256() -> str:
    try:
        raw = ida_nalt.retrieve_input_file_sha256()
        if raw:
            return raw.hex().lower()
    except Exception:
        pass
    path = input_path()
    if path and os.path.exists(path):
        try:
            h = hashlib.sha256()
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(1024 * 1024), b""):
                    h.update(chunk)
            return h.hexdigest()
        except Exception:
            pass
    return ""


def input_path() -> str:
    try:
        return ida_nalt.get_input_file_path() or ""
    except Exception:
        return ""


def input_filename() -> str:
    try:
        return ida_nalt.get_root_filename() or os.path.basename(input_path())
    except Exception:
        return os.path.basename(input_path())


class DragonAnalyzer:
    def __init__(self, rules: dict[str, Any], analysis_mode: str = "auto"):
        self.rules = rules
        self.analysis_mode = analysis_mode if analysis_mode in {key for key, _label in ANALYSIS_MODES} else "auto"
        self.imports_by_ea: dict[int, str] = {}
        self.import_names: set[str] = set()
        self.strings_by_ea: dict[int, str] = {}
        self.critical_strings: list[tuple[int, str]] = []
        self.functions: list[FunctionSummary] = []
        self.findings: list[Finding] = []
        self.correlations: list[dict[str, Any]] = []
        self.primitive_chains: list[PrimitiveChain] = []
        self.pseudocode_by_ea: dict[int, str] = {}
        self.pseudocode_failures: list[dict[str, Any]] = []
        self.decompile_cache: dict[int, str] = {}
        self.decompile_cache_hits = 0
        self.meta: dict[str, Any] = {}
        self.has_hexrays = False

    def run(self, include_pseudocode: bool = False, pseudocode_limit: int = 20, full_scan: bool = False) -> None:
        ida_auto.auto_wait()
        self.findings.clear()
        self.functions.clear()
        self.correlations.clear()
        self.primitive_chains.clear()
        self.pseudocode_by_ea.clear()
        self.pseudocode_failures.clear()
        self.meta = self._collect_meta()
        self.meta["scan_mode"] = "full_scan" if full_scan else ("static_plus_pseudocode" if include_pseudocode else "static")
        self.meta["analysis_mode"] = self.analysis_mode
        self._collect_imports()
        self._collect_strings()
        self._collect_functions()
        self._binary_findings()
        if include_pseudocode:
            limit = len(self.functions) if full_scan else pseudocode_limit
            self.decompile_top_functions(limit, store_text=full_scan, progress=full_scan)
        self._propagate_ioctl_reachability()
        self._build_primitive_chains()
        self.meta["pseudocode_decompiled"] = len(self.pseudocode_by_ea)
        self.meta["pseudocode_failures"] = len(self.pseudocode_failures)
        self.meta["decompile_cache_entries"] = len(self.decompile_cache)
        self.meta["decompile_cache_hits"] = self.decompile_cache_hits
        self.meta["full_scan"] = bool(full_scan)
        self._correlate()
        self.findings.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 0), f.score, f.ea), reverse=True)
        self.functions.sort(key=lambda f: (f.score, f.ea), reverse=True)

    def _collect_meta(self) -> dict[str, Any]:
        sha256 = input_sha256()
        known = self.rules.get("known_hashes", {}).get(sha256.lower()) if sha256 else None
        known_source = "sha256" if known else ""
        if not known:
            known = self._filename_profile(input_filename())
            known_source = "filename_seed" if known else ""
        return {
            "file": input_filename(),
            "path": input_path(),
            "sha256": sha256,
            "known_profile": known or {},
            "known_profile_source": known_source,
            "function_count": len(list(idautils.Functions())),
            "image_base": ea_text(ida_idaapi.get_imagebase()) if hasattr(ida_idaapi, "get_imagebase") else "",
            "is_64bit": bool(idainfo_is_64bit()),
            "hexrays": self._init_hexrays()
        }

    def _filename_profile(self, filename: str) -> dict[str, Any] | None:
        profiles = self.rules.get("filename_profiles", {})
        if dr_logic is not None:
            return dr_logic.match_filename_profile(filename, profiles)
        return None

    def _profile_key(self, value: str) -> str:
        if dr_logic is not None:
            return dr_logic.profile_key(value)
        return re.sub(r"[^a-z0-9.]+", "", value.lower())

    def _init_hexrays(self) -> bool:
        try:
            self.has_hexrays = bool(ida_hexrays.init_hexrays_plugin())
        except Exception:
            self.has_hexrays = False
        return self.has_hexrays

    def _collect_imports(self) -> None:
        self.imports_by_ea.clear()
        self.import_names.clear()
        ordinal_count = 0
        qty = ida_nalt.get_import_module_qty()
        for idx in range(qty):
            module_name = ida_nalt.get_import_module_name(idx) or "import_%d" % idx

            def cb(ea: int, name: str, ordinal: int) -> bool:
                nonlocal ordinal_count
                thunk_name = safe_name(ea)
                if name:
                    item = name
                else:
                    item = "%s!ordinal_%d" % (module_name, ordinal)
                    ordinal_count += 1
                self.imports_by_ea[ea] = item
                self.import_names.add(item)
                if thunk_name and thunk_name != item:
                    self.import_names.add(thunk_name)
                    self.import_names.add("%s:%s" % (item, thunk_name))
                return True

            ida_nalt.enum_import_names(idx, cb)
        if ordinal_count:
            self.meta["ordinal_imports"] = ordinal_count

    def _collect_strings(self) -> None:
        self.strings_by_ea.clear()
        self.critical_strings.clear()
        try:
            strings = idautils.Strings()
            strings.setup(strtypes=None, minlen=4, only_7bit=True)
        except Exception:
            strings = []
        for s in strings:
            try:
                text = str(s)
                ea = int(s.ea)
            except Exception:
                continue
            self.strings_by_ea[ea] = text
            if self._text_has_any(text, CRITICAL_STRINGS):
                self.critical_strings.append((ea, text[:240]))

    def _collect_functions(self) -> None:
        for f_ea in idautils.Functions():
            func = ida_funcs.get_func(f_ea)
            if not func:
                continue
            summary = FunctionSummary(ea=f_ea, name=safe_name(f_ea) or "sub_%X" % f_ea)
            self._inspect_function(func, summary)
            self._score_function(summary)
            self.functions.append(summary)

    def _inspect_function(self, func: Any, summary: FunctionSummary) -> None:
        for ea in idautils.FuncItems(func.start_ea):
            mnem = (idc.print_insn_mnem(ea) or "").lower()
            if mnem:
                summary.mnemonics.add(mnem)
                if mnem in INSTRUCTION_SIGNALS:
                    summary.evidence.append("%s at %s" % (INSTRUCTION_SIGNALS[mnem], ea_text(ea)))
            for cref in idautils.CodeRefsFrom(ea, False):
                cname = self.imports_by_ea.get(cref) or safe_name(cref)
                if cname:
                    summary.calls.add(cname)
                    summary.callees.add(cname)
            for dref in idautils.DataRefsFrom(ea):
                text = self.strings_by_ea.get(dref)
                if text and self._text_has_any(text, CRITICAL_STRINGS):
                    summary.strings.add(text[:160])
            for op_idx in range(4):
                value = self._operand_immediate_value(ea, op_idx)
                if value is None:
                    continue
                decoded = decode_ioctl(value)
                if decoded and decoded not in summary.ioctls:
                    decoded["ea"] = ea
                    summary.ioctls.append(decoded)
        for cref in idautils.CodeRefsTo(func.start_ea, False):
            caller = ida_funcs.get_func(cref)
            if caller and caller.start_ea != func.start_ea:
                summary.callers.add(safe_name(caller.start_ea) or "sub_%X" % caller.start_ea)

    def _operand_immediate_value(self, ea: int, op_idx: int) -> int | None:
        try:
            insn = ida_ua.insn_t()
            if ida_ua.decode_insn(insn, ea) <= 0:
                return None
            op = insn.ops[op_idx]
            if op.type != ida_ua.o_imm:
                return None
            value = int(op.value)
        except Exception:
            return None
        if value < 0 or value > 0xFFFFFFFF:
            return None
        return value

    def _score_function(self, summary: FunctionSummary) -> None:
        text_pool = set(summary.calls) | set(summary.mnemonics) | set(summary.strings)
        for ioctl in summary.ioctls:
            text_pool.add(ioctl["access"])
            text_pool.add(ioctl["method"])
            text_pool.add("IoControlCode")
            if ioctl["access"] == "FILE_ANY_ACCESS" or ioctl["method"] == "METHOD_NEITHER":
                text_pool.add("Parameters.DeviceIoControl")
        self._classify_function(summary, text_pool)
        for family in self.rules.get("families", []):
            if not self._family_enabled_for_mode(family):
                continue
            hits = self._family_hits(family, text_pool)
            min_hits = int(family.get("min_hits", 1) or 1)
            if len(hits) < min_hits:
                continue
            family_id = str(family.get("id", family.get("name", "")))
            if not self._family_hit_actionable(family_id, hits, summary, text_pool):
                continue
            required_any = set()
            for signal in family.get("required_any", []):
                for item in text_pool:
                    if self._signal_matches(str(signal), str(item)):
                        required_any.add(str(signal))
                        break
            if family.get("required_any") and not required_any:
                continue
            negatives = self._family_negative_hits(family, text_pool)
            weight = int(family.get("score", 10))
            score = weight + len(hits) * 3 - len(negatives) * 4
            if any(i["access"] == "FILE_ANY_ACCESS" for i in summary.ioctls):
                score += 8
            if any(i["method"] == "METHOD_NEITHER" for i in summary.ioctls):
                score += 8
            summary.score += max(1, score)
            summary.families.add(family_id or "unknown")
            summary.evidence.extend(sorted(hits))
            finding = Finding(
                severity=severity_from_score(score),
                score=max(1, score),
                ea=summary.ea,
                function=summary.name,
                category=str(family.get("name", family.get("id", "Signal"))),
                signal=", ".join(sorted(hits)[:6]),
                evidence=self._evidence_text(summary, negatives),
                review=str(family.get("review", "")),
                family=family_id,
                confidence_reason="hits=%d negatives=%d ioctls=%d roles=%s" % (
                    len(hits), len(negatives), len(summary.ioctls), ",".join(sorted(summary.roles)[:4]))
            )
            self.findings.append(finding)
        if summary.ioctls and not self._is_runtime_helper(summary):
            risky = [i for i in summary.ioctls if i["access"] == "FILE_ANY_ACCESS" or i["method"] == "METHOD_NEITHER"]
            if risky:
                score = 10 + len(risky) * 4
                summary.score += score
                self.findings.append(Finding(
                    severity=severity_from_score(score),
                    score=score,
                    ea=summary.ea,
                    function=summary.name,
                    category="IOCTL surface",
                    signal="decoded IOCTL constants",
                    evidence=", ".join("%s %s %s" % (i["hex"], i["access"], i["method"]) for i in risky[:8]),
                    review="Decode each IOCTL and verify access requirements, input/output sizes, and authorization.",
                    family="file_any_access_ioctl",
                    confidence_reason="strict decoded IOCTL constants with risky access/method bits"
                ))

    def _family_enabled_for_mode(self, family: dict[str, Any]) -> bool:
        mode = self.analysis_mode
        if mode in {"auto", "universal"}:
            return True
        modes = family.get("modes")
        if not modes:
            modes = ["driver", "universal"]
        normalized = {str(item).lower() for item in modes}
        return mode in normalized or "universal" in normalized

    def _family_hit_actionable(self, family_id: str, hits: set[str], summary: FunctionSummary, text_pool: set[str]) -> bool:
        if dr_logic is not None:
            ok, reason = dr_logic.family_hit_actionable(family_id, hits, bool(summary.ioctls), text_pool)
            if not ok and reason:
                summary.evidence.append(reason)
            return ok
        if family_id == "method_neither_user_pointer":
            if set(hits).issubset(COPY_ONLY_TOKENS) and not summary.ioctls:
                if not any(self._signal_matches(token, item) for token in USER_POINTER_TOKENS for item in text_pool):
                    summary.evidence.append("suppressed-copy-only-user-pointer-fp")
                    return False
        if family_id == "unsafe_copy_length":
            if not any(self._signal_matches(token, item) for token in USER_POINTER_TOKENS for item in text_pool):
                summary.evidence.append("suppressed-copy-without-user-length-fp")
                return False
        if family_id == "registry_service_write":
            if not any(hit in REGISTRY_WRITE_TOKENS for hit in hits):
                summary.evidence.append("registry-open-only-not-write")
                return False
        return True

    def _classify_function(self, summary: FunctionSummary, text_pool: set[str]) -> None:
        role_pool = set(text_pool)
        role_pool.add(summary.name)
        roles = self._roles_from_pool(role_pool)
        if self._is_runtime_helper(summary):
            roles.discard("IOCTL dispatcher")
        elif summary.ioctls:
            roles.add("IOCTL dispatcher")
        if summary.mnemonics & {"wrmsr", "rdmsr"}:
            roles.add("MSR control path")
        if summary.mnemonics & {"in", "out", "ins", "outs"}:
            roles.add("Port/MMIO access path")
        if roles:
            summary.roles.update(roles)
            summary.evidence.extend("role:%s" % role for role in sorted(roles))
            if summary.ioctls and len(roles) > 1:
                summary.score += 5

    def _is_runtime_helper(self, summary: FunctionSummary) -> bool:
        name = (summary.name or "").split("!")[-1].lower()
        if name in NON_DISPATCHER_FUNCTION_NAMES:
            return True
        if name.startswith("__security_") or name.startswith("__report_"):
            return True
        if name.startswith("mem") and name in {"memcpy", "memmove", "memset", "memcmp"}:
            return True
        return False

    def _binary_findings(self) -> None:
        known = self.meta.get("known_profile") or {}
        if known:
            source = self.meta.get("known_profile_source", "")
            primitives = ", ".join(known.get("primitives", []) or [])
            cves = ", ".join(known.get("cves", []) or [])
            projects = ", ".join(known.get("projects", []) or [])
            evidence_parts = [known.get("family", ""), known.get("notes", "")]
            if primitives:
                evidence_parts.append("primitives: " + primitives)
            if cves:
                evidence_parts.append("CVE: " + cves)
            if projects:
                evidence_parts.append("refs/tools: " + projects)
            if source == "filename_seed":
                evidence_parts.append("filename-only profile seed; confirm hash/version before claiming known vulnerable match")
            self.findings.append(Finding(
                severity="Critical" if source == "sha256" else "High",
                score=80 if source == "sha256" else 48,
                ea=idc.BADADDR,
                function="binary",
                category="Known vulnerable profile match" if source == "sha256" else "Known BYOVD filename profile seed",
                signal=known.get("name", "known profile"),
                evidence=" - ".join(part for part in evidence_parts if part),
                review="Use this profile to prioritize manual review. Filename-only matches are triage seeds, not confirmed vulnerability claims.",
                family="known_hash" if source == "sha256" else "filename_profile",
                confidence_reason="profile source=%s" % (source or "unknown")
            ))
        for ea, text in self.critical_strings:
            score = 8
            category = "Interesting string"
            if "CurrentControlSet\\Services" in text or "Registry\\Machine\\System" in text:
                score = 16
                category = "Registry/service-key string"
            elif "\\DosDevices\\" in text or "\\Device\\" in text:
                score = 12
                category = "Device namespace string"
            self.findings.append(Finding(
                severity=severity_from_score(score),
                score=score,
                ea=ea,
                function=safe_name(ida_funcs.get_func(ea).start_ea) if ida_funcs.get_func(ea) else "",
                category=category,
                signal=text[:80],
                evidence=text[:220],
                review="Find xrefs to this string and verify how it is used in device creation, ACLs, registry writes, or IOCTL routing.",
                family="strings",
                confidence_reason="critical string literal xref"
            ))

    def _correlate(self) -> None:
        family_scores: dict[str, dict[str, Any]] = {}
        for fn in self.functions:
            for family in fn.families:
                bucket = family_scores.setdefault(family, {"score": 0, "functions": [], "evidence": set(), "roles": set()})
                bucket["score"] += fn.score
                if len(bucket["functions"]) < 12:
                    bucket["functions"].append({"ea": fn.ea, "name": fn.name, "score": fn.score, "roles": sorted(fn.roles)})
                bucket["evidence"].update(fn.evidence[:20])
                bucket["roles"].update(fn.roles)
        family_by_id = {str(f.get("id")): f for f in self.rules.get("families", [])}
        rows: list[dict[str, Any]] = []
        for family, bucket in family_scores.items():
            rule = family_by_id.get(family, {})
            score = int(bucket["score"])
            roles = sorted(bucket["roles"])
            confidence = min(100, score + min(len(roles) * 4, 16))
            if not any(role in roles for role in ("IOCTL dispatcher", "Minifilter communication port", "WMI/ETW control plane", "ALPC/named port boundary", "Device ACL / namespace exposure")):
                confidence = max(1, confidence - 18)
            rows.append({
                "family": family,
                "name": rule.get("name", family),
                "confidence": confidence,
                "severity": severity_from_score(confidence // 2),
                "functions": bucket["functions"],
                "roles": roles,
                "evidence": sorted(bucket["evidence"])[:20],
                "review": rule.get("review", "")
            })
        self._add_compound_correlations(rows, family_scores)
        rows.sort(key=lambda r: (SEVERITY_ORDER.get(r["severity"], 0), r["confidence"]), reverse=True)
        self.correlations = rows

    def _add_compound_correlations(self, rows: list[dict[str, Any]], family_scores: dict[str, dict[str, Any]]) -> None:
        if dr_logic is not None:
            dr_logic.add_compound_correlations(
                rows,
                family_scores,
                self.meta.get("known_profile") or {},
                self.meta.get("known_profile_source", "")
            )
            return
        patterns = [
            (
                "weak_device_to_memory_primitive",
                "Weak device exposure plus memory primitive",
                {"weak_device_acl"},
                {"physmem_map", "kernel_memory_rw", "mdl_dma_surface", "physical_section_object"},
                "If the device is openable by a low-privileged user and the memory primitive is reachable, this is the highest-value BYOVD review path."
            ),
            (
                "ioctl_user_pointer_to_sink",
                "IOCTL/user-buffer surface plus sensitive sink",
                {"method_neither_user_pointer"},
                {"physmem_map", "kernel_memory_rw", "process_token_sensitive", "process_kill", "registry_service_write", "kernel_patch_or_exec_mapping"},
                "Prioritize data-flow: user buffer/length -> sensitive sink -> missing authorization or incomplete validation."
            ),
            (
                "hardware_control_bundle",
                "Hardware control bundle",
                {"port_io"},
                {"msr_control", "firmware_pci_config", "physmem_map"},
                "Hardware utility pattern. Verify whether IOCTL inputs select MSR index, port/register offset, physical range, width, or write value."
            ),
            (
                "process_control_bundle",
                "Process control / protection bypass bundle",
                {"process_token_sensitive"},
                {"process_kill", "callback_or_filter_tamper", "security_descriptor_write"},
                "Process/EDR-bypass pattern. Use only owned harmless test processes for dynamic proof until authorization boundaries are clear."
            )
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
                "severity": severity_from_score(confidence // 2),
                "functions": functions,
                "roles": sorted(roles),
                "evidence": sorted(evidence)[:24],
                "review": review,
                "compound": True
            })
        profile = self.meta.get("known_profile") or {}
        primitives = profile.get("primitives", []) or []
        if primitives:
            confidence = 75 if self.meta.get("known_profile_source") == "sha256" else 52
            rows.append({
                "family": "profile_guided_review",
                "name": "Known BYOVD primitive profile",
                "confidence": confidence,
                "severity": severity_from_score(confidence // 2),
                "functions": [],
                "roles": [],
                "evidence": ["profile primitives: " + ", ".join(primitives[:10])],
                "review": "Use the profile as a search checklist. Confirm with function-level evidence before reporting.",
                "compound": True
            })

    def _propagate_ioctl_reachability(self) -> None:
        by_name: dict[str, FunctionSummary] = {}
        for fn in self.functions:
            by_name[fn.name] = fn
            by_name[fn.name.split("!")[-1]] = fn
        dispatchers = [
            fn for fn in self.functions
            if not self._is_runtime_helper(fn) and (
                "IOCTL dispatcher" in fn.roles or any(i.get("access") == "FILE_ANY_ACCESS" or i.get("method") == "METHOD_NEITHER" for i in fn.ioctls)
            )
        ]
        graph: dict[int, list[FunctionSummary]] = {}
        for fn in self.functions:
            targets: list[FunctionSummary] = []
            for callee_name in sorted(fn.callees):
                target = by_name.get(callee_name) or by_name.get(callee_name.split("!")[-1])
                if target and target.ea != fn.ea and not self._is_runtime_helper(target):
                    targets.append(target)
            graph[fn.ea] = targets
        seen: set[tuple[int, int]] = set()
        for dispatcher in dispatchers:
            queue: list[tuple[FunctionSummary, int]] = [(target, 1) for target in graph.get(dispatcher.ea, [])]
            visited: set[int] = {dispatcher.ea}
            while queue:
                target, depth = queue.pop(0)
                if target.ea in visited:
                    continue
                visited.add(target.ea)
                key = (dispatcher.ea, target.ea)
                target.callers.add(dispatcher.name)
                sensitive_families = target.families & SENSITIVE_REACHABILITY_FAMILIES
                sensitive_roles = target.roles & SENSITIVE_REACHABILITY_ROLES
                if key not in seen and (sensitive_families or sensitive_roles):
                    seen.add(key)
                    target.roles.add("IOCTL-reachable callee candidate")
                    target.score += 8
                    target.evidence.append("reachable-from-ioctl:%s depth=%d" % (dispatcher.name, depth))
                    self.findings.append(Finding(
                        severity=severity_from_score(18 + min(target.score, 20)),
                        score=18,
                        ea=target.ea,
                        function=target.name,
                        category="IOCTL reachability",
                        signal=dispatcher.name,
                        evidence="Called by IOCTL dispatcher candidate %s; roles=%s; families=%s" % (
                            "%s depth=%d" % (dispatcher.name, depth),
                            ", ".join(sorted(target.roles)[:8]),
                            ", ".join(sorted(target.families)[:8])),
                        review="Trace arguments from the dispatcher into this callee. Confirm whether caller-controlled IOCTL fields reach the sensitive primitive.",
                        family="ioctl_reachability",
                        confidence_reason="callgraph depth=%d from dispatcher candidate" % depth
                    ))
                if depth < 4:
                    for nxt in graph.get(target.ea, []):
                        if nxt.ea not in visited:
                            queue.append((nxt, depth + 1))

    def _build_primitive_chains(self) -> None:
        self.primitive_chains.clear()
        dispatchers = [
            fn for fn in self.functions
            if not self._is_runtime_helper(fn) and (
                bool(fn.roles & ENTRY_SURFACE_ROLES)
                or any(i.get("access") == "FILE_ANY_ACCESS" or i.get("method") == "METHOD_NEITHER" for i in fn.ioctls)
            )
        ]
        dispatcher_names = {fn.name for fn in dispatchers}
        seen: set[tuple[int, int, str]] = set()
        for target in self.functions:
            if self._is_runtime_helper(target):
                continue
            sensitive_families = sorted(target.families & SENSITIVE_REACHABILITY_FAMILIES)
            sensitive_roles = sorted(target.roles & SENSITIVE_REACHABILITY_ROLES)
            if not sensitive_families and not sensitive_roles:
                continue
            callers = sorted(target.callers & dispatcher_names)
            if not callers and (target.roles & ENTRY_SURFACE_ROLES):
                callers = [target.name]
            for caller_name in callers[:8]:
                entry = next((fn for fn in dispatchers if fn.name == caller_name), target)
                primitive = ", ".join(sensitive_roles[:4] or sensitive_families[:4])
                access_surface = self._access_surface_text(entry, target)
                confidence = self._chain_confidence(entry, target)
                key = (entry.ea, target.ea, primitive)
                if key in seen:
                    continue
                seen.add(key)
                self.primitive_chains.append(PrimitiveChain(
                    severity=severity_from_score(confidence // 2),
                    confidence=confidence,
                    entry=entry.name,
                    entry_ea=entry.ea,
                    target=target.name,
                    target_ea=target.ea,
                    primitive=primitive,
                    access_surface=access_surface,
                    evidence=", ".join(sorted(set(target.evidence))[:12]),
                    proof_focus=self._proof_focus_for_chain(target),
                    chain_type="pseudocode" if "Pseudocode" in access_surface or target.pseudocode_facts or entry.pseudocode_facts else "strict",
                    confidence_reason=self._chain_confidence_reason(entry, target)
                ))
        if not self.primitive_chains and (self.meta.get("known_profile") or {}).get("name"):
            entries = [
                fn for fn in self.functions
                if "Device ACL / namespace exposure" in fn.roles or "Driver entry / device setup" in fn.roles
            ]
            targets = [
                fn for fn in self.functions
                if not self._is_runtime_helper(fn) and (fn.families & SENSITIVE_REACHABILITY_FAMILIES or fn.roles & SENSITIVE_REACHABILITY_ROLES)
            ]
            entry = entries[0] if entries else None
            if entry:
                for target in sorted(targets, key=lambda fn: fn.score, reverse=True)[:12]:
                    if target.ea == entry.ea:
                        continue
                    primitive = ", ".join(sorted((target.roles & SENSITIVE_REACHABILITY_ROLES) or (target.families & SENSITIVE_REACHABILITY_FAMILIES))[:4])
                    confidence = min(70, 35 + min(target.score // 4, 25))
                    self.primitive_chains.append(PrimitiveChain(
                        severity=severity_from_score(confidence // 2),
                        confidence=confidence,
                        entry=entry.name,
                        entry_ea=entry.ea,
                        target=target.name,
                        target_ea=target.ea,
                        primitive=primitive,
                        access_surface="Known local vulnerable profile; dispatcher not recovered automatically",
                        evidence=", ".join(sorted(set(target.evidence))[:10]),
                        proof_focus=self._proof_focus_for_chain(target),
                        chain_type="profile_seed",
                        confidence_reason="profile-guided fallback: known vulnerable profile plus sensitive primitive, dispatcher not recovered"
                    ))
        self.primitive_chains.sort(key=lambda c: (SEVERITY_ORDER.get(c.severity, 0), c.confidence), reverse=True)

    def _access_surface_text(self, entry: FunctionSummary, target: FunctionSummary) -> str:
        ioctls = entry.ioctls or target.ioctls
        if not ioctls:
            facts = entry.pseudocode_facts or target.pseudocode_facts
            if facts.get("ioctl_surface"):
                return "Pseudocode IOCTL surface: %s" % ", ".join(facts.get("ioctl_surface", [])[:5])
            for key, label in (
                ("rpc_surface", "RPC surface"),
                ("named_pipe_surface", "Named pipe surface"),
                ("com_surface", "COM/DCOM surface"),
                ("alpc_surface", "ALPC/named port surface"),
                ("hypercall_sinks", "Hypercall surface"),
                ("vmbus_surface", "VMBus/virtual device surface"),
            ):
                if facts.get(key):
                    return "%s: %s" % (label, ", ".join(facts.get(key, [])[:5]))
            if entry.roles & ENTRY_SURFACE_ROLES:
                return "Entry surface role: %s" % ", ".join(sorted(entry.roles & ENTRY_SURFACE_ROLES))
            if entry.evidence:
                dispatch_evidence = [e for e in entry.evidence if "dispatch-assignment" in e or "reachable-from-ioctl" in e]
                if dispatch_evidence:
                    return ", ".join(dispatch_evidence[:4])
            return "No strict entry constant decoded; verify dispatcher/interface manually"
        risky = [i for i in ioctls if i.get("access") == "FILE_ANY_ACCESS" or i.get("method") == "METHOD_NEITHER"]
        selected = risky[:4] if risky else ioctls[:4]
        return ", ".join("%s %s %s" % (i.get("hex", ""), i.get("access", ""), i.get("method", "")) for i in selected)

    def _chain_confidence(self, entry: FunctionSummary, target: FunctionSummary) -> int:
        score = 35
        if "Device ACL / namespace exposure" in entry.roles:
            score += 15
        if "IOCTL dispatcher" in entry.roles:
            score += 12
        if entry.roles & (ENTRY_SURFACE_ROLES - {"IOCTL dispatcher", "Device ACL / namespace exposure"}):
            score += 10
        if entry.pseudocode_facts.get("ioctl_surface"):
            score += 8
        if target.pseudocode_facts.get("guards"):
            score -= 10
        if any(i.get("access") == "FILE_ANY_ACCESS" for i in entry.ioctls + target.ioctls):
            score += 12
        if any(i.get("method") == "METHOD_NEITHER" for i in entry.ioctls + target.ioctls):
            score += 10
        score += min(len(target.families & SENSITIVE_REACHABILITY_FAMILIES) * 8, 28)
        score += min(len(target.roles & SENSITIVE_REACHABILITY_ROLES) * 6, 24)
        if self._family_negative_hits({"negative_signals": ["IoValidateDeviceIoControlAccess", "SeSinglePrivilegeCheck", "SePrivilegeCheck", "ProbeForRead", "ProbeForWrite"]}, set(target.calls) | set(target.strings)):
            score -= 18
        return max(1, min(100, score))

    def _chain_confidence_reason(self, entry: FunctionSummary, target: FunctionSummary) -> str:
        reasons = []
        if "Device ACL / namespace exposure" in entry.roles:
            reasons.append("device namespace/ACL surface")
        if "IOCTL dispatcher" in entry.roles:
            reasons.append("IOCTL dispatcher")
        other_surfaces = sorted(entry.roles & (ENTRY_SURFACE_ROLES - {"IOCTL dispatcher", "Device ACL / namespace exposure"}))
        if other_surfaces:
            reasons.append("entry surface=%s" % ",".join(other_surfaces[:3]))
        if entry.pseudocode_facts.get("ioctl_surface"):
            reasons.append("pseudocode IOCTL surface")
        if any(i.get("access") == "FILE_ANY_ACCESS" for i in entry.ioctls + target.ioctls):
            reasons.append("FILE_ANY_ACCESS")
        if any(i.get("method") == "METHOD_NEITHER" for i in entry.ioctls + target.ioctls):
            reasons.append("METHOD_NEITHER")
        if target.families & SENSITIVE_REACHABILITY_FAMILIES:
            reasons.append("families=%s" % ",".join(sorted(target.families & SENSITIVE_REACHABILITY_FAMILIES)[:4]))
        if target.roles & SENSITIVE_REACHABILITY_ROLES:
            reasons.append("roles=%s" % ",".join(sorted(target.roles & SENSITIVE_REACHABILITY_ROLES)[:4]))
        if target.pseudocode_facts.get("guards"):
            reasons.append("guard tokens present, verify dominance")
        return "; ".join(reasons) if reasons else "scored from entry/target roles and evidence"

    def _proof_focus_for_chain(self, target: FunctionSummary) -> str:
        families = target.families
        roles = target.roles
        if "physmem_map" in families or "Physical memory mapper" in roles:
            return "Prove caller-controlled physical/MMIO range, mapping size, cache type, and missing privilege gate."
        if "mdl_dma_surface" in families or "MDL/DMA boundary" in roles:
            return "Prove caller-controlled address/length/process context reaches MDL/DMA mapping and lifetime is safe."
        if "port_io" in families or "Port/MMIO access path" in roles:
            return "Prove caller-controlled port/register offset and width; confirm low-privileged reachability."
        if "registry_service_write" in families or "Registry/service-key writer" in roles:
            return "Prove low-privileged caller can cause privileged registry/service-key access without direct rights."
        if "process_token_sensitive" in families or "Process/token object path" in roles:
            return "Prove caller-controlled PID/handle/token input and missing desired-access/privilege validation."
        if "process_kill" in families or "Process termination / protection bypass" in roles:
            return "Prove caller-controlled target process selection using only an owned harmless test process, then document direct-denial vs driver-mediated termination rights."
        if "firmware_environment" in families or "Firmware/PCI/bus access" in roles:
            return "Prove caller-controlled firmware/PCI/bus selector and missing admin/privilege gate."
        if "rpc_interface_surface" in families or "RPC interface surface" in roles:
            return "Recover RPC UUID/opnum and prove low-privileged binding/reachability before testing one authorized method path."
        if "named_pipe_surface" in families or "Named pipe IPC surface" in roles:
            return "Prove low-privileged pipe connect/write, then trace one message field into a privileged service action."
        if "com_dcom_surface" in families or "COM/DCOM activation surface" in roles:
            return "Recover CLSID/AppID permissions and prove low-privileged activation/reachability of one privileged method."
        if "impersonation_boundary" in families or "Impersonation boundary" in roles:
            return "Prove impersonation level/client identity handling and whether privileged actions run under the intended token."
        if "privileged_file_op" in families or "Privileged file/symlink operation" in roles:
            return "Prove caller-controlled path reaches a SYSTEM file operation with direct-denial and reparse/hardlink controls."
        if "hypercall_surface" in families or "Hypervisor hypercall surface" in roles:
            return "Map one hypercall number and prove guest-controlled input reaches the parser with bounds/privilege checks documented."
        if "vmbus_packet_surface" in families or "VMBus packet parser" in roles:
            return "Recover one VMBus packet/message layout and prove length/type fields are validated before parser use."
        if "toctou_user_buffer" in families or "TOCTOU user-buffer race candidate" in roles:
            return "Prove check/use split by showing the same user-controlled field is validated and later reread from the original source."
        return "Prove dispatcher reachability, caller-controlled input, missing authorization, and reversible impact."

    def decompile_top_functions(self, limit: int = 20, store_text: bool = False, progress: bool = False) -> list[tuple[int, str]]:
        if not self.has_hexrays and not self._init_hexrays():
            return []
        out: list[tuple[int, str]] = []
        ordered = sorted(self.functions, key=lambda f: f.score, reverse=True)
        if limit > 0:
            ordered = ordered[:limit]
        total = len(ordered)
        if progress:
            self._show_wait("Dragon Reverse Full Scan: decompiling %d functions..." % total)
        try:
            for idx, summary in enumerate(ordered, 1):
                if progress:
                    self._pump_ui()
                if progress and (idx == 1 or idx % 5 == 0 or idx == total):
                    self._replace_wait("Dragon Reverse Full Scan: decompiling %d/%d\n%s" % (idx, total, summary.name))
                    if self._user_cancelled():
                        self.meta["scan_cancelled"] = True
                        break
                text = self.decompile_function(summary.ea)
                if not text:
                    continue
                if text.startswith("Decompile failed"):
                    self.pseudocode_failures.append({"ea": summary.ea, "ea_text": ea_text(summary.ea), "function": summary.name, "error": text})
                    if store_text:
                        self.pseudocode_by_ea[summary.ea] = text
                    continue
                if store_text:
                    self.pseudocode_by_ea[summary.ea] = text
                new_ioctl_count = 0
                if not self._is_runtime_helper(summary):
                    new_ioctl_count = self._merge_pseudocode_ioctls(summary, text)
                    self._apply_dispatch_assignments_from_text(summary, text)
                facts = {} if self._is_runtime_helper(summary) else self._pseudocode_facts(text)
                summary.pseudocode_facts = facts
                summary.proof_notes = self._pseudocode_proof_notes(facts)
                hits = [] if self._is_runtime_helper(summary) else self._actionable_pseudocode_hits(self._pseudocode_hits(text), facts)
                roles = set() if self._is_runtime_helper(summary) else (self._roles_from_text(text) | self._roles_from_pseudocode_facts(facts))
                summary.pseudocode_hits = hits
                if new_ioctl_count:
                    summary.roles.add("IOCTL dispatcher")
                    ioctl_score = 12 + min(new_ioctl_count * 4, 24)
                    summary.score += ioctl_score
                    self.findings.append(Finding(
                        severity=severity_from_score(ioctl_score),
                        score=ioctl_score,
                        ea=summary.ea,
                        function=summary.name,
                        category="Pseudocode IOCTL constants",
                        signal=", ".join(i.get("hex", "") for i in summary.ioctls[-new_ioctl_count:]),
                        evidence="Strict assembly scan missed these values, but Hex-Rays pseudocode contains CTL_CODE-shaped constants.",
                        review="Decode each recovered IOCTL and verify access bits, method, input/output lengths, and authorization gates.",
                        family="file_any_access_ioctl",
                        confidence_reason="Hex-Rays pseudocode CTL_CODE-shaped constants"
                    ))
                if roles:
                    new_roles = roles - summary.roles
                    summary.roles.update(roles)
                    summary.evidence.extend("pseudo-role:%s" % role for role in sorted(new_roles))
                    role_score = 8 + len(new_roles) * 2
                    if new_roles:
                        summary.score += role_score
                        self.findings.append(Finding(
                            severity=severity_from_score(role_score),
                            score=role_score,
                            ea=summary.ea,
                            function=summary.name,
                            category="Pseudocode role inference",
                            signal=", ".join(sorted(new_roles)[:8]),
                            evidence="Hex-Rays pseudo-code suggests review roles for this function.",
                            review="Use inferred roles to pivot faster. Confirm each role against xrefs, arguments, and caller-controlled data.",
                        family="pseudocode_roles",
                        confidence_reason="role tokens inferred from decompiled pseudocode"
                    ))
                deep_score = 0 if self._is_runtime_helper(summary) else self._pseudocode_risk_score(summary, facts)
                if deep_score >= 14:
                    summary.score += deep_score
                    self.findings.append(Finding(
                        severity=severity_from_score(deep_score),
                        score=deep_score,
                        ea=summary.ea,
                        function=summary.name,
                        category="Deep pseudocode hypothesis",
                        signal=self._pseudocode_fact_signal(facts),
                        evidence=self._pseudocode_fact_evidence(facts),
                        review="Confirm data flow manually: source buffer/length -> sensitive sink, then check guards, caller mode, authorization, and reversible proof path.",
                        family="pseudocode_deep",
                        confidence_reason="structured pseudocode facts score=%d" % deep_score
                    ))
                if not self._is_runtime_helper(summary) and self._missing_caller_mode_gate(summary, facts):
                    gate_score = 34
                    summary.score += gate_score
                    summary.evidence.append("missing-caller-mode-gate-hypothesis")
                    self.findings.append(Finding(
                        severity=severity_from_score(gate_score),
                        score=gate_score,
                        ea=summary.ea,
                        function=summary.name,
                        category="Caller-mode gate review",
                        signal="PreviousMode/RequestorMode not visible",
                        evidence="Sensitive pseudocode facts are user/IOCTL-facing, but no PreviousMode, RequestorMode, or ExGetPreviousMode token was observed.",
                        review="High-priority review: confirm whether user-mode callers are rejected or privileged operations are gated before the sink. Absence in pseudocode is not final proof.",
                        family="missing_caller_mode_gate",
                        confidence_reason="user/IOCTL surface + sensitive sink + no caller-mode token in pseudocode facts"
                    ))
                if not self._is_runtime_helper(summary) and facts.get("probe_size_mismatch"):
                    probe_score = 32 + min(len(facts.get("probe_size_mismatch", [])) * 2, 10)
                    summary.score += probe_score
                    summary.evidence.append("probe-size-mismatch-hypothesis")
                    self.findings.append(Finding(
                        severity=severity_from_score(probe_score),
                        score=probe_score,
                        ea=summary.ea,
                        function=summary.name,
                        category="Probe size review",
                        signal=", ".join(facts.get("probe_size_mismatch", [])[:3]),
                        evidence="ProbeForRead/ProbeForWrite size appears smaller than the recovered IOCTL structure footprint, or could not be reconciled safely.",
                        review="Verify that ProbeForRead/ProbeForWrite covers every field read on every METHOD_NEITHER/user-pointer path. A mismatch is a high-priority overflow/OOB hypothesis, not standalone proof.",
                        family="probe_size_review",
                        confidence_reason="recovered struct footprint compared to ProbeForRead/ProbeForWrite size argument"
                    ))
                if hits:
                    score = 10 + len(hits) * 2
                    summary.score += score
                    self.findings.append(Finding(
                        severity=severity_from_score(score),
                        score=score,
                        ea=summary.ea,
                        function=summary.name,
                        category="Pseudocode verifier",
                        signal=", ".join(hits[:8]),
                        evidence="Pseudo-code contains driver trust-boundary tokens.",
                        review="Use this as a manual review queue. Confirm control flow, caller mode, lengths, and privilege checks in ctree/pseudocode.",
                        family="pseudocode",
                        confidence_reason="actionable pseudocode tokens with sensitive facts"
                    ))
                out.append((summary.ea, text))
        finally:
            if progress:
                self._hide_wait()
        self.findings.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 0), f.score, f.ea), reverse=True)
        return out

    def _merge_pseudocode_ioctls(self, summary: FunctionSummary, text: str) -> int:
        seen = {(int(item.get("value", 0)), int(item.get("ea", summary.ea))) for item in summary.ioctls}
        added = 0
        for value, source in self._recover_pseudocode_ioctl_values(text):
            decoded = decode_ioctl(value)
            if not decoded:
                continue
            key = (int(decoded["value"]), summary.ea)
            if key in seen:
                continue
            seen.add(key)
            decoded["ea"] = summary.ea
            decoded["source"] = source
            summary.ioctls.append(decoded)
            summary.evidence.append("pseudo-ioctl:%s" % decoded["hex"])
            if source != "pseudocode":
                summary.evidence.append("recovered-ioctl-source:%s" % source)
            added += 1
        return added

    def _recover_pseudocode_ioctl_values(self, text: str) -> list[tuple[int, str]]:
        values: list[tuple[int, str]] = []
        seen: set[int] = set()

        def add(value: int, source: str) -> None:
            if value <= 0 or value > 0xFFFFFFFF or value in seen:
                return
            seen.add(value)
            values.append((value, source))

        for match in re.finditer(r"\b0x[0-9A-Fa-f]{6,8}\b|\b\d{7,10}\b", text):
            raw = match.group(0)
            try:
                add(int(raw, 16 if raw.lower().startswith("0x") else 10), "pseudocode")
            except Exception:
                continue

        for match in re.finditer(r"CTL_CODE\s*\(([^;\n]+?)\)", text, re.IGNORECASE):
            args = self._split_call_args(match.group(1))
            if len(args) >= 4:
                parts = [self._eval_ioctl_expr(arg) for arg in args[:4]]
                if all(part is not None for part in parts):
                    dev, func, method, access = [int(part) for part in parts]
                    add(((dev & 0xFFFF) << 16) | ((access & 3) << 14) | ((func & 0xFFF) << 2) | (method & 3), "pseudocode_ctl_code_macro")

        for line in text.splitlines():
            if "<<" not in line or not ("|" in line or "+" in line):
                continue
            if not any(marker in line for marker in ("16", "14", "2", "METHOD_", "FILE_")):
                continue
            value = self._eval_ioctl_expr(line)
            if value is not None:
                add(value, "pseudocode_bit_expr")
        return values

    def _split_call_args(self, text: str) -> list[str]:
        args: list[str] = []
        depth = 0
        start = 0
        for idx, ch in enumerate(text):
            if ch == "(":
                depth += 1
            elif ch == ")" and depth:
                depth -= 1
            elif ch == "," and depth == 0:
                args.append(text[start:idx].strip())
                start = idx + 1
        tail = text[start:].strip()
        if tail:
            args.append(tail)
        return args

    def _eval_ioctl_expr(self, expr: str) -> int | None:
        cleaned = expr
        cleaned = cleaned.split("//", 1)[0]
        cleaned = re.sub(r"/\*.*?\*/", "", cleaned)
        cleaned = re.sub(r"\([A-Za-z_][A-Za-z0-9_:\s\*]+\)", "", cleaned)
        for token, value in CTL_CODE_TOKEN_VALUES.items():
            cleaned = re.sub(r"\b%s\b" % re.escape(token), str(value), cleaned)
        cleaned = cleaned.replace("u", "").replace("U", "").replace("l", "").replace("L", "")
        matches = re.findall(r"0x[0-9A-Fa-f]+|\d+|<<|>>|\||&|\^|\+|\-|\(|\)", cleaned)
        if not matches:
            return None
        safe = " ".join(matches)
        if not re.fullmatch(r"[0-9A-Fa-fxX\s<>\|\&\^\+\-\(\)]+", safe):
            return None
        try:
            value = int(eval(safe, {"__builtins__": {}}, {}))
        except Exception:
            return None
        return value if 0 < value <= 0xFFFFFFFF else None

    def _apply_dispatch_assignments_from_text(self, owner: FunctionSummary, text: str) -> None:
        targets = self._extract_device_control_dispatch_targets(text)
        if not targets:
            return
        by_name: dict[str, FunctionSummary] = {}
        for fn in self.functions:
            by_name[fn.name] = fn
            by_name[fn.name.split("!")[-1]] = fn
        for target_name in targets:
            target = by_name.get(target_name) or by_name.get(target_name.split("!")[-1])
            if not target or self._is_runtime_helper(target):
                continue
            if "IOCTL dispatcher" not in target.roles:
                target.roles.add("IOCTL dispatcher")
                target.score += 22
                target.evidence.append("dispatch-assignment-from-pseudocode:%s" % owner.name)
                target.callers.add(owner.name)
                self.findings.append(Finding(
                    severity="Medium",
                    score=22,
                    ea=target.ea,
                    function=target.name,
                    category="Pseudocode dispatch assignment",
                    signal="MajorFunction[IRP_MJ_DEVICE_CONTROL]",
                    evidence="%s assigns device-control dispatch to %s" % (owner.name, target.name),
                    review="Inspect this function as the primary IOCTL dispatcher. Decode comparisons/switch cases and trace caller-controlled buffers into callees.",
                    family="ioctl_dispatch_assignment",
                    confidence_reason="Hex-Rays dispatch assignment MajorFunction[IRP_MJ_DEVICE_CONTROL]"
                ))

    def _extract_device_control_dispatch_targets(self, text: str) -> set[str]:
        targets: set[str] = set()
        patterns = [
            r"MajorFunction\s*\[\s*(?:14|0xE|IRP_MJ_DEVICE_CONTROL)\s*\]\s*=\s*(?:\([^)]*\)\s*)?&?([A-Za-z_?$@][A-Za-z0-9_?$@]*)",
            r"IRP_MJ_DEVICE_CONTROL[^\n=]{0,80}=\s*(?:\([^)]*\)\s*)?&?([A-Za-z_?$@][A-Za-z0-9_?$@]*)",
        ]
        for pattern in patterns:
            for match in re.finditer(pattern, text, re.IGNORECASE):
                name = match.group(1)
                if name and name not in {"DriverObject", "MajorFunction", "NULL"}:
                    targets.add(name)
        return targets

    def _pseudocode_facts(self, text: str) -> dict[str, list[str]]:
        facts: dict[str, list[str]] = {}
        lower = text.lower()
        for group, tokens in PSEUDOCODE_FACT_GROUPS.items():
            hits = []
            for token in tokens:
                if token.lower() in lower:
                    hits.append(token)
            if hits:
                facts[group] = sorted(set(hits))
        caller_mode = sorted({token for token in CALLER_MODE_GUARD_TOKENS if token.lower() in lower})
        if caller_mode:
            facts["caller_mode_guards"] = caller_mode
        dispatch_targets = sorted(self._extract_device_control_dispatch_targets(text))
        if dispatch_targets:
            facts["dispatch_assignments"] = dispatch_targets
            facts.setdefault("ioctl_surface", []).append("MajorFunction[IRP_MJ_DEVICE_CONTROL]")
            facts["ioctl_surface"] = sorted(set(facts["ioctl_surface"]))
        edges = self._ctree_lite_dataflow_edges(text)
        if edges:
            facts["ctree_lite_dataflow"] = edges
        uuids = self._recover_uuid_literals(text)
        if uuids:
            facts["uuid_or_clsid_literals"] = uuids
        toctou = self._detect_toctou_candidates(text)
        if toctou:
            facts["toctou_candidates"] = toctou
        fields = self._recover_ioctl_struct_fields(text)
        if fields:
            facts["ioctl_struct_fields"] = fields
        probe_checks, probe_mismatches = self._recover_probe_size_checks(text, fields)
        if probe_checks:
            facts["probe_size_checks"] = probe_checks
        if probe_mismatches:
            facts["probe_size_mismatch"] = probe_mismatches
        path_validation = self._path_validation_summary(text)
        if path_validation:
            facts["path_validation"] = path_validation
        return facts

    def _recover_uuid_literals(self, text: str) -> list[str]:
        out = []
        seen: set[str] = set()
        for match in re.finditer(r"\{?[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}?", text):
            value = match.group(0).strip("{}").lower()
            if value not in seen:
                seen.add(value)
                out.append(value)
        return out[:20]

    def _detect_toctou_candidates(self, text: str) -> list[str]:
        aliases = self._pseudocode_source_aliases(text)
        if not aliases:
            return []
        lines = text.splitlines()
        field_reads: dict[str, list[int]] = {}
        guard_lines: set[int] = set()
        guard_terms = ("if", "<", ">", "==", "!=", "<=", ">=", "ProbeForRead", "ProbeForWrite", "InputBufferLength", "OutputBufferLength")
        local_copy_terms = ("memcpy", "RtlCopyMemory", "memmove", "RtlMoveMemory")
        for idx, line in enumerate(lines, 1):
            stripped = line.strip()
            if any(term in stripped for term in guard_terms):
                guard_lines.add(idx)
            for var in aliases:
                for match in re.finditer(r"\b%s\s*(?:->\s*([A-Za-z_][A-Za-z0-9_]*)|\+\s*(0x[0-9A-Fa-f]+|\d+))" % re.escape(var), stripped):
                    field = match.group(1) or match.group(2) or "base"
                    key = "%s.%s" % (var, field)
                    field_reads.setdefault(key, []).append(idx)
        out: list[str] = []
        for field, reads in sorted(field_reads.items(), key=lambda kv: (len(kv[1]), kv[0]), reverse=True):
            unique_reads = sorted(set(reads))
            if len(unique_reads) < 2:
                continue
            first, last = unique_reads[0], unique_reads[-1]
            if last - first < 2:
                continue
            has_guard_before = any(line <= first + 1 for line in guard_lines)
            window_text = "\n".join(lines[max(0, first - 2):min(len(lines), last + 2)])
            has_local_copy = any(term.lower() in window_text.lower() for term in local_copy_terms)
            if has_guard_before and not has_local_copy:
                out.append("toctou-user-buffer-reread field=%s first_line=%d last_line=%d reads=%d" % (
                    field, first, last, len(unique_reads)))
        return out[:12]

    def _ctree_lite_dataflow_edges(self, text: str) -> list[str]:
        source_tokens = set(PSEUDOCODE_FACT_GROUPS.get("user_buffers", []) + PSEUDOCODE_FACT_GROUPS.get("length_fields", []))
        sink_tokens: list[str] = []
        for group in ("memory_sinks", "copy_sinks", "port_sinks", "registry_sinks", "token_sinks", "process_kill_sinks", "firmware_sinks", "exec_sinks", "rpc_surface", "named_pipe_surface", "com_surface", "alpc_surface", "impersonation_sinks", "file_sinks", "hypercall_sinks", "vmbus_surface"):
            sink_tokens.extend(PSEUDOCODE_FACT_GROUPS.get(group, []))
        source_vars = self._pseudocode_source_aliases(text)
        edges: list[str] = []
        ignored = self._pseudocode_ignored_names()
        lines = text.splitlines()
        for idx, line in enumerate(lines, 1):
            matched_sink = next((token for token in sink_tokens if token.lower() in line.lower()), "")
            if not matched_sink:
                continue
            names = set(re.findall(r"\b[A-Za-z_][A-Za-z0-9_]*\b", line))
            used = sorted((names & source_vars) - ignored)
            if used:
                args = self._call_args_for_sink(line, matched_sink)
                detail = (" args=%s" % args[:140]) if args else ""
                edges.append("line %d: %s -> %s%s" % (idx, ",".join(used[:5]), matched_sink, detail))
            elif any(token.lower() in line.lower() for token in source_tokens):
                edges.append("line %d: direct user-field -> %s" % (idx, matched_sink))
        return edges[:20]

    def _pseudocode_ignored_names(self) -> set[str]:
        return {
            "if", "for", "while", "return", "sizeof", "char", "int", "unsigned", "signed",
            "void", "const", "volatile", "struct", "SystemBuffer", "Type3InputBuffer",
            "UserBuffer", "InputBufferLength", "OutputBufferLength", "Parameters",
            "DeviceIoControl", "CurrentStackLocation", "Irp", "IRP", "PVOID"
        }

    def _pseudocode_source_aliases(self, text: str) -> set[str]:
        source_tokens = set(PSEUDOCODE_FACT_GROUPS.get("user_buffers", []) + PSEUDOCODE_FACT_GROUPS.get("length_fields", []))
        aliases: set[str] = set()
        ignored = self._pseudocode_ignored_names()
        lines = text.splitlines()
        assign_re = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+?);?$")
        for _round in range(4):
            changed = False
            for line in lines:
                stripped = line.strip()
                lower = stripped.lower()
                match = assign_re.search(stripped)
                if any(token.lower() in lower for token in source_tokens):
                    for name in re.findall(r"\b[A-Za-z_][A-Za-z0-9_]*\b", stripped):
                        if name not in ignored and not name.startswith("__") and len(name) > 1:
                            if name not in aliases:
                                aliases.add(name)
                                changed = True
                    if match:
                        lhs = match.group(1)
                        if lhs not in ignored and lhs not in aliases:
                            aliases.add(lhs)
                            changed = True
                    continue
                if match:
                    lhs, rhs = match.group(1), match.group(2)
                    if lhs not in ignored and lhs not in aliases:
                        rhs_names = set(re.findall(r"\b[A-Za-z_][A-Za-z0-9_]*\b", rhs))
                        if rhs_names & aliases:
                            aliases.add(lhs)
                            changed = True
            if not changed:
                break
        return aliases

    def _call_args_for_sink(self, line: str, sink: str) -> str:
        pattern = re.escape(sink) + r"\s*\((.*)\)"
        match = re.search(pattern, line, re.IGNORECASE)
        if not match:
            return ""
        return ", ".join(self._split_call_args(match.group(1))[:6])

    def _recover_ioctl_struct_fields(self, text: str) -> list[str]:
        aliases = self._pseudocode_source_aliases(text)
        if not aliases:
            return []
        fields: dict[int, dict[str, Any]] = {}
        lines = text.splitlines()
        for idx, line in enumerate(lines, 1):
            nearby = "\n".join(lines[max(0, idx - 2):min(len(lines), idx + 3)])
            role = self._guess_field_role(nearby)
            for match in re.finditer(r"\*\(\s*([A-Za-z_][A-Za-z0-9_\s]*\s*\*+)\s*\)\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\+\s*(0x[0-9A-Fa-f]+|\d+)\s*\)", line):
                ctype, var, raw_off = match.group(1), match.group(2), match.group(3)
                if var not in aliases:
                    continue
                off = int(raw_off, 16 if raw_off.lower().startswith("0x") else 10)
                self._record_struct_field(fields, off, ctype, role, idx, line)
            for match in re.finditer(r"\(\s*([A-Za-z_][A-Za-z0-9_\s]*)\s*\*\s*\)\s*([A-Za-z_][A-Za-z0-9_]*)\s*\+\s*(\d+)", line):
                ctype, var, raw_idx = match.group(1), match.group(2), match.group(3)
                if var not in aliases:
                    continue
                size = self._ctype_size(ctype)
                off = int(raw_idx) * size
                self._record_struct_field(fields, off, ctype, role, idx, line)
            for match in re.finditer(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*->\s*([A-Za-z_][A-Za-z0-9_]*)", line):
                var, field_name = match.group(1), match.group(2)
                if var not in aliases:
                    continue
                pseudo_off = 0x100000 + len(fields)
                self._record_struct_field(fields, pseudo_off, "unknown", role or field_name, idx, line, display_name=field_name)
        out = []
        for off in sorted(fields):
            item = fields[off]
            if off >= 0x100000:
                name = item.get("display_name", "named_field")
                off_text = "named:%s" % name
            else:
                name = "field_%03X" % off
                off_text = "+0x%X" % off
            variant_suffix = ""
            variants = item.get("variants", []) or []
            if len(variants) > 1:
                variant_suffix = " variants=%s union_candidate=yes" % self._format_struct_variants(variants)
            out.append("%s %s size=%s role=%s lines=%s ctype=%s%s" % (
                off_text,
                name,
                item.get("size", "?"),
                item.get("role", "unknown"),
                ",".join(str(v) for v in item.get("lines", [])[:5]),
                item.get("ctype", "unknown"),
                variant_suffix))
        return out[:30]

    def _record_struct_field(self, fields: dict[int, dict[str, Any]], off: int, ctype: str, role: str, line_no: int, line: str, display_name: str = "") -> None:
        clean_ctype = self._compact_ctype(ctype)
        clean_role = self._safe_struct_token(role or "unknown")
        size = self._ctype_size(ctype)
        item = fields.setdefault(off, {
            "size": size,
            "ctype": clean_ctype,
            "role": clean_role,
            "lines": [],
            "samples": [],
            "display_name": display_name,
            "variants": [],
        })
        variant = {"ctype": clean_ctype, "size": size, "role": clean_role}
        if not any(v.get("ctype") == clean_ctype and int(v.get("size", 0) or 0) == size and v.get("role") == clean_role for v in item.get("variants", [])):
            item.setdefault("variants", []).append(variant)
        if item.get("role") == "unknown" and clean_role:
            item["role"] = clean_role
        if clean_role != "unknown" and item.get("role") != clean_role and item.get("role") == "unknown":
            item["role"] = clean_role
        if size > int(item.get("size", 0) or 0):
            item["size"] = size
            item["ctype"] = clean_ctype
        elif item.get("ctype") == "unknown" and clean_ctype != "unknown":
            item["ctype"] = clean_ctype
        if line_no not in item["lines"]:
            item["lines"].append(line_no)
        if len(item["samples"]) < 3:
            item["samples"].append(line.strip()[:160])

    def _compact_ctype(self, ctype: str) -> str:
        clean = " ".join(str(ctype or "unknown").split())
        clean = clean.replace(" *", "*").replace("* ", "*")
        return self._safe_struct_token(clean)

    def _safe_struct_token(self, value: str) -> str:
        out = re.sub(r"[^A-Za-z0-9_\*\[\]]+", "_", str(value or "unknown")).strip("_")
        return out or "unknown"

    def _format_struct_variants(self, variants: list[dict[str, Any]]) -> str:
        parts = []
        seen: set[str] = set()
        for variant in variants[:8]:
            ctype = self._safe_struct_token(str(variant.get("ctype", "unknown")))
            role = self._safe_struct_token(str(variant.get("role", "unknown")))
            size = int(variant.get("size", 0) or 0)
            part = "%s:%d:%s" % (ctype, size, role)
            if part not in seen:
                seen.add(part)
                parts.append(part)
        return ";".join(parts)

    def _ctype_size(self, ctype: str) -> int:
        clean = " ".join(str(ctype).replace("*", " ").split())
        for token, size in PSEUDOCODE_TYPE_SIZES.items():
            if token.lower() in clean.lower():
                return size
        return 8 if idainfo_is_64bit() else 4

    def _recover_probe_size_checks(self, text: str, fields: list[str]) -> tuple[list[str], list[str]]:
        estimated = self._estimated_struct_size_from_fields(fields)
        if estimated <= 0 and "ProbeFor" not in text:
            return [], []
        checks: list[str] = []
        mismatches: list[str] = []
        lines = text.splitlines()
        for idx, line in enumerate(lines, 1):
            for probe in ("ProbeForRead", "ProbeForWrite"):
                if probe.lower() not in line.lower():
                    continue
                args = self._call_args_list(line, probe)
                if len(args) < 2:
                    checks.append("line %d: %s args-unparsed" % (idx, probe))
                    continue
                ptr_expr = args[0].strip()
                size_expr = args[1].strip()
                status = self._probe_size_status(size_expr, estimated)
                detail = "line %d: %s ptr=%s size=%s estimated_struct=0x%X status=%s" % (
                    idx,
                    probe,
                    self._short_expr(ptr_expr),
                    self._short_expr(size_expr),
                    estimated,
                    status)
                checks.append(detail)
                if status.startswith("under-probe") or status.startswith("unresolved-fixed-small") or status.startswith("missing-size"):
                    mismatches.append(detail)
        return checks[:20], mismatches[:20]

    def _call_args_list(self, line: str, sink: str) -> list[str]:
        pattern = re.escape(sink) + r"\s*\((.*)\)"
        match = re.search(pattern, line, re.IGNORECASE)
        if not match:
            return []
        return self._split_call_args(match.group(1))

    def _short_expr(self, expr: str, limit: int = 80) -> str:
        out = " ".join(str(expr or "").split())
        return out if len(out) <= limit else out[:limit - 3] + "..."

    def _probe_size_status(self, size_expr: str, estimated: int) -> str:
        expr = size_expr.strip()
        if not expr:
            return "missing-size"
        lower = expr.lower()
        if "sizeof" in lower:
            return "sizeof-review"
        if any(token.lower() in lower for token in PSEUDOCODE_FACT_GROUPS.get("length_fields", [])):
            return "dynamic-length-review"
        value = self._eval_size_expr(expr)
        if value is None:
            return "unresolved-size-review"
        if estimated > 0 and value < estimated:
            return "under-probe-fixed-size-0x%X-vs-struct-0x%X" % (value, estimated)
        if estimated > 0 and value > estimated:
            return "covers-estimated-struct-fixed-size-0x%X-vs-struct-0x%X" % (value, estimated)
        if estimated > 0 and value == estimated:
            return "matches-estimated-struct-0x%X" % estimated
        if value in {0, 1, 2, 4}:
            return "unresolved-fixed-small-0x%X" % value
        return "fixed-size-0x%X-review" % value

    def _eval_size_expr(self, expr: str) -> int | None:
        cleaned = expr
        cleaned = cleaned.split("//", 1)[0]
        cleaned = re.sub(r"/\*.*?\*/", "", cleaned)
        cleaned = cleaned.replace("ui64", "").replace("i64", "")
        cleaned = cleaned.replace("u", "").replace("U", "").replace("l", "").replace("L", "")
        if re.search(r"[A-Za-z_]", cleaned):
            return None
        matches = re.findall(r"0x[0-9A-Fa-f]+|\d+|<<|>>|\||&|\^|\+|\-|\*|/|\(|\)", cleaned)
        if not matches:
            return None
        safe = " ".join(matches)
        if not re.fullmatch(r"[0-9A-Fa-fxX\s<>\|\&\^\+\-\*\/\(\)]+", safe):
            return None
        try:
            value = int(eval(safe, {"__builtins__": {}}, {}))
        except Exception:
            return None
        return value if 0 <= value <= 0x1000000 else None

    def _estimated_struct_size_from_fields(self, fields: list[str]) -> int:
        max_end = 0
        for raw in fields or []:
            off_match = re.search(r"\+0x([0-9A-Fa-f]+)\s+", raw)
            if not off_match:
                continue
            offset = int(off_match.group(1), 16)
            sizes = []
            size_match = re.search(r"\bsize=(\d+)", raw)
            if size_match:
                sizes.append(int(size_match.group(1)))
            variants_match = re.search(r"\bvariants=([^\s]+)", raw)
            if variants_match:
                for variant in variants_match.group(1).split(";"):
                    parts = variant.split(":")
                    if len(parts) >= 2:
                        try:
                            sizes.append(int(parts[1]))
                        except Exception:
                            pass
            size = max(sizes) if sizes else (8 if idainfo_is_64bit() else 4)
            max_end = max(max_end, offset + max(size, 1))
        return max_end

    def _guess_field_role(self, text: str) -> str:
        lower = text.lower()
        if "mmmapiospace" in lower or "physical" in lower or "mmgetphysicaladdress" in lower:
            return "physical_address_or_range"
        if "mmmaplockedpagesspecifycache" in lower or "ioallocatemdl" in lower or "mdl" in lower:
            return "mdl_address_or_length"
        if "inputbufferlength" in lower or "outputbufferlength" in lower or "length" in lower or "size" in lower:
            return "size_or_length"
        if "__in" in lower or "__out" in lower or "read_port" in lower or "write_port" in lower or "port" in lower:
            return "port_or_register"
        if "zwterminateprocess" in lower or "pslookupprocessbyprocessid" in lower or "pid" in lower:
            return "pid_or_handle"
        if "zwsetvaluekey" in lower or "rtlwriteregistryvalue" in lower:
            return "registry_value"
        return "unknown"

    def _path_validation_summary(self, text: str) -> list[str]:
        guard_tokens = PSEUDOCODE_FACT_GROUPS.get("guards", [])
        sink_tokens: list[str] = []
        for group in PSEUDOCODE_SENSITIVE_GROUPS | {"copy_sinks"}:
            sink_tokens.extend(PSEUDOCODE_FACT_GROUPS.get(group, []))
        lines = text.splitlines()
        results: list[str] = []
        for idx, line in enumerate(lines):
            sink = next((token for token in sink_tokens if token.lower() in line.lower()), "")
            if not sink:
                continue
            window = "\n".join(lines[max(0, idx - 8):idx + 1]).lower()
            guards = [token for token in guard_tokens if token.lower() in window]
            if guards:
                results.append("line %d: %s guarded-by %s" % (idx + 1, sink, ",".join(guards[:4])))
            else:
                results.append("line %d: %s no-nearby-guard-in-pseudocode-window" % (idx + 1, sink))
        return results[:20]

    def _path_validation_has_missing_nearby_guard(self, facts: dict[str, list[str]]) -> bool:
        return any(
            "no-nearby-guard-in-pseudocode-window" in item or "no-guard-in-window" in item
            for item in facts.get("path_validation", [])
        )

    def _missing_caller_mode_gate(self, summary: FunctionSummary, facts: dict[str, list[str]]) -> bool:
        if not facts:
            return False
        if facts.get("caller_mode_guards"):
            return False
        has_surface = bool(facts.get("ioctl_surface") or facts.get("user_buffers") or facts.get("length_fields") or summary.ioctls)
        if not has_surface:
            return False
        high_value_groups = {
            "memory_sinks", "port_sinks", "token_sinks", "process_kill_sinks", "firmware_sinks", "exec_sinks",
            "rpc_surface", "named_pipe_surface", "com_surface", "alpc_surface", "impersonation_sinks",
            "file_sinks", "hypercall_sinks", "vmbus_surface"
        }
        return any(facts.get(group) for group in high_value_groups)

    def _roles_from_pseudocode_facts(self, facts: dict[str, list[str]]) -> set[str]:
        roles: set[str] = set()
        ioctl_hits = facts.get("ioctl_surface") or []
        if any("MajorFunction" not in hit for hit in ioctl_hits):
            roles.add("IOCTL dispatcher")
        if facts.get("memory_sinks"):
            roles.add("Physical memory mapper")
        if facts.get("port_sinks"):
            roles.add("Port/MMIO access path")
        if facts.get("registry_sinks"):
            roles.add("Registry/service-key writer")
        if facts.get("token_sinks"):
            roles.add("Process/token object path")
        if facts.get("process_kill_sinks"):
            roles.add("Process termination / protection bypass")
        if facts.get("firmware_sinks"):
            roles.add("Firmware/PCI/bus access")
        if facts.get("exec_sinks"):
            roles.add("Executable mapping / patch surface")
        if facts.get("rpc_surface"):
            roles.add("RPC interface surface")
        if facts.get("named_pipe_surface"):
            roles.add("Named pipe IPC surface")
        if facts.get("com_surface"):
            roles.add("COM/DCOM activation surface")
        if facts.get("alpc_surface"):
            roles.add("ALPC/named port boundary")
        if facts.get("impersonation_sinks"):
            roles.add("Impersonation boundary")
        if facts.get("file_sinks"):
            roles.add("Privileged file/symlink operation")
        if facts.get("hypercall_sinks"):
            roles.add("Hypervisor hypercall surface")
        if facts.get("vmbus_surface"):
            roles.add("VMBus packet parser")
        if facts.get("toctou_candidates"):
            roles.add("TOCTOU user-buffer race candidate")
        if any(token in (facts.get("memory_sinks") or []) for token in ("IoAllocateMdl", "MmProbeAndLockPages", "MmBuildMdlForNonPagedPool", "MmMapLockedPagesSpecifyCache")):
            roles.add("MDL/DMA boundary")
        return roles

    def _actionable_pseudocode_hits(self, hits: list[str], facts: dict[str, list[str]]) -> list[str]:
        if not hits:
            return []
        if not self._facts_have_sensitive_signal(facts):
            return []
        if set(hits).issubset(COPY_ONLY_TOKENS) and not (facts.get("user_buffers") or facts.get("length_fields")):
            return []
        return hits

    def _facts_have_sensitive_signal(self, facts: dict[str, list[str]]) -> bool:
        return any(facts.get(group) for group in PSEUDOCODE_SENSITIVE_GROUPS) or bool(facts.get("copy_sinks") and (facts.get("user_buffers") or facts.get("length_fields")))

    def _pseudocode_risk_score(self, summary: FunctionSummary, facts: dict[str, list[str]]) -> int:
        if not facts:
            return 0
        score = 0
        has_surface = bool(
            facts.get("ioctl_surface") or facts.get("user_buffers") or facts.get("length_fields") or summary.ioctls
            or facts.get("rpc_surface") or facts.get("named_pipe_surface") or facts.get("com_surface")
            or facts.get("alpc_surface") or facts.get("hypercall_sinks") or facts.get("vmbus_surface")
        )
        sensitive_groups = [group for group in PSEUDOCODE_SENSITIVE_GROUPS if facts.get(group)]
        if facts.get("dispatch_assignments"):
            score += 14
        if has_surface:
            score += 8
        if facts.get("user_buffers"):
            score += 8
        if facts.get("length_fields"):
            score += 6
        score += min(len(sensitive_groups) * 10, 35)
        if facts.get("memory_sinks"):
            score += 10
        if facts.get("copy_sinks") and (facts.get("user_buffers") or facts.get("length_fields")):
            score += 8
        if facts.get("ctree_lite_dataflow"):
            score += min(len(facts["ctree_lite_dataflow"]) * 8, 24)
        if facts.get("toctou_candidates"):
            score += 20
        if facts.get("uuid_or_clsid_literals"):
            score += 4
        if facts.get("ioctl_struct_fields"):
            score += min(len(facts["ioctl_struct_fields"]) * 3, 18)
        if facts.get("probe_size_checks"):
            score += 4
        if facts.get("probe_size_mismatch"):
            score += 18
        if self._missing_caller_mode_gate(summary, facts):
            score += 16
        if facts.get("path_validation") and self._path_validation_has_missing_nearby_guard(facts):
            score += 8
        if facts.get("copy_sinks") and not (facts.get("user_buffers") or facts.get("length_fields") or summary.ioctls):
            score -= 10
        if facts.get("registry_open") and not facts.get("registry_sinks"):
            score -= 12
        if not facts.get("guards") and (has_surface or sensitive_groups):
            score += 8
        if facts.get("guards"):
            score -= min(len(facts["guards"]) * 4, 16)
        return max(0, min(60, score))

    def _pseudocode_fact_signal(self, facts: dict[str, list[str]]) -> str:
        pieces = []
        for group in ("ioctl_surface", "rpc_surface", "named_pipe_surface", "com_surface", "alpc_surface", "hypercall_sinks", "vmbus_surface", "user_buffers", "length_fields", "ctree_lite_dataflow", "toctou_candidates", "uuid_or_clsid_literals", "ioctl_struct_fields", "probe_size_mismatch", "probe_size_checks", "path_validation", "memory_sinks", "port_sinks", "registry_sinks", "token_sinks", "process_kill_sinks", "firmware_sinks", "exec_sinks", "impersonation_sinks", "file_sinks", "caller_mode_guards", "guards"):
            if facts.get(group):
                pieces.append("%s=%s" % (group, ",".join(facts[group][:3])))
        return " | ".join(pieces[:4]) if pieces else "pseudo-code facts"

    def _pseudocode_fact_evidence(self, facts: dict[str, list[str]]) -> str:
        if not facts:
            return "No structured pseudocode facts extracted."
        parts = []
        for group in sorted(facts):
            parts.append("%s: %s" % (group, ", ".join(facts[group][:8])))
        return " | ".join(parts)

    def _pseudocode_proof_notes(self, facts: dict[str, list[str]]) -> list[str]:
        notes: list[str] = []
        if facts.get("dispatch_assignments"):
            notes.append("Dispatcher assignment found: review this target before lower-level primitive callees.")
        if facts.get("rpc_surface"):
            notes.append("RPC server surface visible; recover interface UUID, endpoint/protseq, opnums, auth callback, and impersonation behavior.")
        if facts.get("named_pipe_surface"):
            notes.append("Named pipe surface visible; recover pipe name, SDDL/default DACL, and low-privileged connect/write matrix.")
        if facts.get("com_surface"):
            notes.append("COM/DCOM surface visible; recover CLSID/AppID, launch/access permissions, authentication level, and privileged methods.")
        if facts.get("alpc_surface"):
            notes.append("ALPC/named port surface visible; recover port name, security descriptor, message layout, and security QoS.")
        if facts.get("hypercall_sinks"):
            notes.append("Hypercall surface visible; map hypercall numbers, guest-controlled registers/buffers, and partition/VP context.")
        if facts.get("vmbus_surface"):
            notes.append("VMBus/virtual device parser signals visible; recover packet headers, message types, ring-buffer bounds, and length arithmetic.")
        if facts.get("toctou_candidates"):
            notes.append("TOCTOU lite candidate visible; confirm whether validation reads a user-controlled field and later rereads it from the original source.")
        if facts.get("uuid_or_clsid_literals"):
            notes.append("UUID/CLSID literals recovered; classify each as RPC interface ID, COM class/AppID, or unrelated GUID via xrefs.")
        if facts.get("user_buffers") or facts.get("length_fields"):
            notes.append("Potential caller-controlled data is visible; trace buffer pointer and length together.")
        if facts.get("ctree_lite_dataflow"):
            notes.append("Ctree-lite dataflow edge found; verify the variable flow in Hex-Rays ctree/assembly before claiming reachability.")
        if facts.get("ioctl_struct_fields"):
            notes.append("IOCTL structure field candidates recovered from buffer offsets; use them to draft the request struct and verify each field at the sink.")
        if facts.get("probe_size_checks"):
            notes.append("ProbeForRead/ProbeForWrite calls were compared against the recovered structure footprint; confirm exact dominance and size semantics manually.")
        if facts.get("probe_size_mismatch"):
            notes.append("Probe size mismatch hypothesis present: verify whether the probed byte count covers the largest recovered field offset plus size.")
        if facts.get("path_validation"):
            notes.append("Path-sensitive lite validation recorded nearby guard tokens only; missing-nearby-guard findings are review priorities, not proof that validation is absent.")
        if any(facts.get(group) for group in ("memory_sinks", "port_sinks", "token_sinks", "process_kill_sinks", "firmware_sinks", "exec_sinks")):
            if facts.get("caller_mode_guards"):
                notes.append("Caller-mode tokens present; verify they gate the sensitive sink on every user-reachable path.")
            else:
                notes.append("No PreviousMode/RequestorMode token found near sensitive pseudocode facts; prioritize caller-mode gate review.")
        if facts.get("memory_sinks"):
            notes.append("Memory mapping/copy sink visible; verify range, cache type, process context, and ownership.")
        if facts.get("copy_sinks"):
            notes.append("Copy sink visible; confirm copy length source and output buffer bounds.")
        if facts.get("port_sinks"):
            notes.append("Port/register sink visible; confirm caller cannot select arbitrary offset/width/value.")
        if facts.get("process_kill_sinks"):
            notes.append("Process termination sink visible; prove with a harmless owned test process before any protected-process claim.")
        if facts.get("impersonation_sinks"):
            notes.append("Impersonation sink visible; verify token level, client identity, and RevertToSelf/error cleanup.")
        if facts.get("file_sinks"):
            notes.append("Privileged file-operation sink visible; verify final path, reparse point, hardlink, ACL, and direct-denial controls.")
        if facts.get("registry_sinks"):
            notes.append("Registry write sink visible; use read-only before/after collection until a reversible test exists.")
        elif facts.get("registry_open"):
            notes.append("Registry open only; do not claim write impact without a write sink or controlled side effect.")
        if facts.get("guards"):
            notes.append("Mitigation signals present: verify they dominate every risky path, not only one branch.")
        else:
            notes.append("No obvious guard token in pseudocode; confirm in Hex-Rays ctree/assembly before treating validation as missing.")
        return notes

    def _show_wait(self, text: str) -> None:
        try:
            ida_kernwin.show_wait_box(text)
        except Exception:
            pass

    def _replace_wait(self, text: str) -> None:
        try:
            ida_kernwin.replace_wait_box(text)
        except Exception:
            pass

    def _hide_wait(self) -> None:
        try:
            ida_kernwin.hide_wait_box()
        except Exception:
            pass

    def _user_cancelled(self) -> bool:
        try:
            return bool(ida_kernwin.user_cancelled())
        except Exception:
            return False

    def _pump_ui(self) -> None:
        try:
            QtWidgets.QApplication.processEvents()
        except Exception:
            pass

    def decompile_function(self, ea: int) -> str:
        if not self.has_hexrays and not self._init_hexrays():
            return ""
        func = ida_funcs.get_func(ea)
        if not func:
            return ""
        start_ea = int(func.start_ea)
        if start_ea in self.decompile_cache:
            self.decompile_cache_hits += 1
            return self.decompile_cache[start_ea]
        try:
            cfunc = ida_hexrays.decompile(start_ea)
            lines = []
            for line in cfunc.get_pseudocode():
                raw = getattr(line, "line", line)
                lines.append(safe_tag_remove(raw))
            text = "\n".join(lines)
        except Exception as exc:
            text = "Decompile failed at %s: %s" % (ea_text(start_ea), exc)
        self.decompile_cache[start_ea] = text
        return text

    def markdown_report(self) -> str:
        lines = [
            "# Dragon Reverse Report",
            "",
            "File: `%s`" % self.meta.get("file", ""),
            "Path: `%s`" % self.meta.get("path", ""),
            "SHA256: `%s`" % self.meta.get("sha256", ""),
            "Functions: `%s`" % self.meta.get("function_count", ""),
            "Hex-Rays: `%s`" % ("available" if self.meta.get("hexrays") else "not available"),
            "",
            "## Interpretation Guardrails",
            ""
        ]
        lines.extend("- %s" % item for item in TRIAGE_GUARDRAILS)
        lines.append("")
        known = self.meta.get("known_profile") or {}
        if known:
            lines += [
                "## Known Profile Match",
                "",
                "- Name: `%s`" % known.get("name", ""),
                "- Family: `%s`" % known.get("family", ""),
                "- Notes: %s" % known.get("notes", ""),
                ""
            ]
        lines += [
            "## Correlations",
            "",
            "| Severity | Confidence | Family | Roles | Review |",
            "| --- | ---: | --- | --- | --- |"
        ]
        for row in self.correlations[:20]:
            lines.append("| %s | %d | %s | %s | %s |" % (
                row["severity"],
                row["confidence"],
                row["name"],
                ", ".join(row.get("roles", [])).replace("|", "/"),
                row["review"].replace("|", "/")))
        lines += [
            "",
            "## Primitive Chains",
            "",
            "| Severity | Confidence | Type | Status | Entry | Target | Primitive | Access Surface | Proof Focus |",
            "| --- | ---: | --- | --- | --- | --- | --- | --- | --- |"
        ]
        for chain in self.primitive_chains[:40]:
            lines.append("| %s | %d | %s | %s | %s | %s | %s | %s | %s |" % (
                chain.severity,
                chain.confidence,
                chain.chain_type,
                chain.review_status,
                ("%s %s" % (ea_text(chain.entry_ea), chain.entry)).replace("|", "/"),
                ("%s %s" % (ea_text(chain.target_ea), chain.target)).replace("|", "/"),
                chain.primitive.replace("|", "/"),
                chain.access_surface.replace("|", "/"),
                chain.proof_focus.replace("|", "/")))
        lines += [
            "",
            "## Findings",
            "",
            "| Severity | Score | EA | Function | Category | Signal | Evidence |",
            "| --- | ---: | --- | --- | --- | --- | --- |"
        ]
        for finding in self.findings[:120]:
            lines.append("| %s | %d | %s | %s | %s | %s | %s |" % (
                finding.severity,
                finding.score,
                ea_text(finding.ea),
                finding.function.replace("|", "/"),
                finding.category.replace("|", "/"),
                finding.signal.replace("|", "/"),
                finding.evidence.replace("|", "/")[:240]
            ))
        lines += [
            "",
            "## Top Functions",
            "",
            "| Score | EA | Function | Roles | Families | Evidence |",
            "| ---: | --- | --- | --- | --- | --- |"
        ]
        for fn in self.functions[:80]:
            lines.append("| %d | %s | %s | %s | %s | %s |" % (
                fn.score,
                ea_text(fn.ea),
                fn.name.replace("|", "/"),
                ", ".join(sorted(fn.roles)).replace("|", "/"),
                ", ".join(sorted(fn.families)),
                ", ".join(sorted(set(fn.evidence)))[:240].replace("|", "/")
            ))
        lines.append("")
        lines.append("Scores are triage hints, not vulnerability claims. chain_type=pseudocode and no-nearby-guard-in-pseudocode-window require manual/dynamic proof.")
        return "\n".join(lines)

    def as_json(self) -> dict[str, Any]:
        return {
            "meta": self.meta,
            "correlations": self.correlations,
            "primitive_chains": [chain.__dict__ for chain in self.primitive_chains],
            "findings": [finding.__dict__ for finding in self.findings],
            "functions": [
                {
                    "ea": fn.ea,
                    "name": fn.name,
                    "score": fn.score,
                    "roles": sorted(fn.roles),
                    "families": sorted(fn.families),
                    "calls": sorted(fn.calls),
                    "callers": sorted(fn.callers),
                    "callees": sorted(fn.callees),
                    "mnemonics": sorted(fn.mnemonics),
                    "strings": sorted(fn.strings),
                    "ioctls": fn.ioctls,
                    "evidence": sorted(set(fn.evidence)),
                    "pseudocode_hits": fn.pseudocode_hits,
                    "pseudocode_facts": fn.pseudocode_facts,
                    "proof_notes": fn.proof_notes,
                    "confidence_reason": fn.confidence_reason,
                    "review_status": fn.review_status
                }
                for fn in self.functions
            ],
            "pseudocode_failures": self.pseudocode_failures,
            "pseudocode_texts_available": len(self.pseudocode_by_ea)
        }

    def _evidence_text(self, summary: FunctionSummary, negatives: Iterable[str]) -> str:
        pieces = []
        if summary.roles:
            pieces.append("roles: " + ", ".join(sorted(summary.roles)[:6]))
        if summary.calls:
            pieces.append("calls: " + ", ".join(sorted(summary.calls)[:8]))
        if summary.mnemonics & set(INSTRUCTION_SIGNALS):
            pieces.append("insn: " + ", ".join(sorted(summary.mnemonics & set(INSTRUCTION_SIGNALS))))
        if summary.ioctls:
            pieces.append("ioctl: " + ", ".join("%s/%s/%s" % (i["hex"], i["access"], i["method"]) for i in summary.ioctls[:5]))
        if summary.strings:
            pieces.append("strings: " + ", ".join(sorted(summary.strings)[:3]))
        neg = sorted(set(negatives))
        if neg:
            pieces.append("mitigating signals present: " + ", ".join(neg[:5]))
        return " | ".join(pieces)[:600]

    def _family_hits(self, family: dict[str, Any], pool: set[str]) -> set[str]:
        hits: set[str] = set()
        for signal in family.get("signals", []):
            for item in pool:
                if self._signal_matches(str(signal), str(item)):
                    hits.add(str(signal))
                    break
        return hits

    def _family_negative_hits(self, family: dict[str, Any], pool: set[str]) -> set[str]:
        hits: set[str] = set()
        for signal in family.get("negative_signals", []):
            for item in pool:
                if self._signal_matches(str(signal), str(item)):
                    hits.add(str(signal))
                    break
        return hits

    def _signal_matches(self, signal: str, item: str) -> bool:
        sig = signal.lower()
        value = item.lower()
        if not sig or not value:
            return False
        exact_tokens = {
            "in", "out", "ins", "outs", "cli", "sti", "try", "__try",
            "wd", "ba", "sy", "%p", "pci", "acpi", "wpp"
        }
        if sig in exact_tokens or len(sig) <= 3:
            return value == sig or value.endswith("!" + sig)
        if "\\" in sig or " " in sig or "%" in sig:
            return sig in value
        if value == sig or value.endswith("!" + sig) or value.endswith("_" + sig):
            return True
        # API names often appear with import-module decoration or decompiler casts.
        if re.match(r"^[a-z_][a-z0-9_]*$", sig):
            return bool(re.search(r"(^|[^a-z0-9_])%s([^a-z0-9_]|$)" % re.escape(sig), value))
        return sig in value

    def _pseudocode_hits(self, text: str) -> list[str]:
        lower = text.lower()
        return sorted({token for token in PSEUDOCODE_TOKENS if token.lower() in lower})

    def _roles_from_pool(self, pool: set[str]) -> set[str]:
        roles: set[str] = set()
        for role, signals in ROLE_RULES:
            hits = 0
            for signal in signals:
                if any(self._signal_matches(signal, item) for item in pool):
                    hits += 1
            if hits >= 1:
                roles.add(role)
        return roles

    def _roles_from_text(self, text: str) -> set[str]:
        roles: set[str] = set()
        lower = text.lower()
        for role, signals in ROLE_RULES:
            hits = 0
            for signal in signals:
                sig = signal.lower()
                if sig in {"in", "out"}:
                    continue
                if sig in lower:
                    hits += 1
            if role == "IOCTL dispatcher":
                if "iocontrolcode" in lower and ("switch" in lower or "case " in lower or "type3inputbuffer" in lower or "systembuffer" in lower):
                    roles.add(role)
                elif hits >= 2:
                    roles.add(role)
            elif hits >= 1:
                roles.add(role)
        return roles

    def _text_has_any(self, text: str, needles: Iterable[str]) -> bool:
        lower = text.lower()
        return any(str(n).lower() in lower for n in needles)


def idainfo_is_64bit() -> bool:
    try:
        return ida_idaapi.inf_is_64bit()
    except Exception:
        try:
            return ida_idaapi.get_inf_structure().is_64bit()
        except Exception:
            return False


class DragonPseudocodeHighlighter(QtGui.QSyntaxHighlighter):
    def __init__(self, document: QtGui.QTextDocument):
        super().__init__(document)
        self.rules: list[tuple[re.Pattern[str], QtGui.QTextCharFormat]] = []
        self._build_rules()

    def _fmt(self, color: str, bold: bool = False, italic: bool = False) -> QtGui.QTextCharFormat:
        fmt = QtGui.QTextCharFormat()
        fmt.setForeground(QtGui.QColor(color))
        if bold:
            fmt.setFontWeight(QtGui.QFont.Bold)
        if italic:
            fmt.setFontItalic(True)
        return fmt

    def _build_rules(self) -> None:
        sink_fmt = self._fmt("#b42318", bold=True)
        source_fmt = self._fmt("#1d4ed8", bold=True)
        guard_fmt = self._fmt("#166534", bold=True)
        ioctl_fmt = self._fmt("#7c3aed", bold=True)
        warn_fmt = self._fmt("#b45309", bold=True)
        struct_fmt = self._fmt("#0f766e", bold=True)

        sink_tokens: list[str] = []
        for group in PSEUDOCODE_SENSITIVE_GROUPS | {"copy_sinks"}:
            sink_tokens.extend(PSEUDOCODE_FACT_GROUPS.get(group, []))
        source_tokens = PSEUDOCODE_FACT_GROUPS.get("user_buffers", []) + PSEUDOCODE_FACT_GROUPS.get("length_fields", [])
        guard_tokens = list(PSEUDOCODE_FACT_GROUPS.get("guards", [])) + sorted(CALLER_MODE_GUARD_TOKENS)
        ioctl_tokens = ["IoControlCode", "CTL_CODE", "FILE_ANY_ACCESS", "METHOD_NEITHER", "IRP_MJ_DEVICE_CONTROL"]

        for token in sorted(set(sink_tokens), key=len, reverse=True):
            self.rules.append((re.compile(r"\b%s\b" % re.escape(token), re.IGNORECASE), sink_fmt))
        for token in sorted(set(source_tokens), key=len, reverse=True):
            self.rules.append((re.compile(r"\b%s\b" % re.escape(token), re.IGNORECASE), source_fmt))
        for token in sorted(set(guard_tokens), key=len, reverse=True):
            self.rules.append((re.compile(r"\b%s\b" % re.escape(token), re.IGNORECASE), guard_fmt))
        for token in ioctl_tokens:
            self.rules.append((re.compile(r"\b%s\b" % re.escape(token), re.IGNORECASE), ioctl_fmt))
        self.rules.append((re.compile(r"0x[0-9A-Fa-f]{6,8}"), ioctl_fmt))
        self.rules.append((re.compile(r"no-nearby-guard-in-pseudocode-window|missing-caller-mode-gate-hypothesis", re.IGNORECASE), warn_fmt))
        self.rules.append((re.compile(r"field_[0-9A-Fa-f]{3}|ioctl_struct_fields|typedef struct", re.IGNORECASE), struct_fmt))

    def highlightBlock(self, text: str) -> None:
        for pattern, fmt in self.rules:
            for match in pattern.finditer(text):
                self.setFormat(match.start(), match.end() - match.start(), fmt)


class DragonReverseWidget(QtWidgets.QWidget):
    def __init__(self, parent: QtWidgets.QWidget | None = None):
        super().__init__(parent)
        self.rules = load_rules()
        self.analyzer = DragonAnalyzer(self.rules, "auto")
        self.lol_matches: list[dict[str, Any]] = []
        self.analysis_running = False
        self._build_ui()

    def _build_ui(self) -> None:
        self.setObjectName("DragonReverseRoot")
        self._apply_theme()
        root = QtWidgets.QVBoxLayout(self)
        root.setContentsMargins(10, 10, 10, 10)
        root.setSpacing(8)

        toolbar = QtWidgets.QHBoxLayout()
        self.mode_combo = QtWidgets.QComboBox()
        for mode_key, mode_label in ANALYSIS_MODES:
            self.mode_combo.addItem(mode_label, mode_key)
        self.mode_combo.setMinimumWidth(120)
        self.run_btn = QtWidgets.QPushButton("Run static analysis")
        self.run_pseudo_btn = QtWidgets.QPushButton("Run + pseudocode")
        self.full_scan_btn = QtWidgets.QPushButton("Full Scan")
        self.fetch_lol_btn = QtWidgets.QPushButton("Fetch LOLDrivers match")
        self.export_json_btn = QtWidgets.QPushButton("Export JSON")
        self.export_md_btn = QtWidgets.QPushButton("Export Markdown")
        self.export_full_report_btn = QtWidgets.QPushButton("Export full report")
        toolbar.addWidget(QtWidgets.QLabel("Mode"))
        toolbar.addWidget(self.mode_combo)
        for btn in (self.run_btn, self.run_pseudo_btn, self.full_scan_btn, self.fetch_lol_btn, self.export_json_btn, self.export_md_btn, self.export_full_report_btn):
            btn.setMinimumHeight(26)
            toolbar.addWidget(btn)
        self.full_scan_btn.setProperty("primary", True)
        self.export_full_report_btn.setProperty("accent", True)
        toolbar.addStretch(1)
        root.addLayout(toolbar)

        self.status = QtWidgets.QLabel("Ready. Load a Windows driver IDB and run analysis.")
        self.status.setObjectName("StatusLabel")
        root.addWidget(self.status)

        legend = QtWidgets.QHBoxLayout()
        legend.setSpacing(6)
        for severity in ("Critical", "High", "Medium", "Low", "Info"):
            legend.addWidget(self._severity_chip(severity))
        legend.addStretch(1)
        root.addLayout(legend)

        self.tabs = QtWidgets.QTabWidget()
        self.tabs.setObjectName("MainTabs")
        root.addWidget(self.tabs, 1)

        dashboard_widget = QtWidgets.QWidget()
        dashboard_layout = QtWidgets.QVBoxLayout(dashboard_widget)
        dashboard_toolbar = QtWidgets.QHBoxLayout()
        self.copy_dashboard_btn = QtWidgets.QPushButton("Copy tab")
        dashboard_toolbar.addWidget(self.copy_dashboard_btn)
        dashboard_toolbar.addStretch(1)
        dashboard_layout.addLayout(dashboard_toolbar)
        self.dashboard = QtWidgets.QTextBrowser()
        self.dashboard.setOpenExternalLinks(True)
        dashboard_layout.addWidget(self.dashboard, 1)
        self.tabs.addTab(dashboard_widget, "Dashboard")

        attack_widget = QtWidgets.QWidget()
        attack_layout = QtWidgets.QVBoxLayout(attack_widget)
        attack_toolbar = QtWidgets.QHBoxLayout()
        self.copy_attack_surface_btn = QtWidgets.QPushButton("Copy table")
        self.copy_attack_surface_selected_btn = QtWidgets.QPushButton("Copy selected")
        attack_toolbar.addWidget(self.copy_attack_surface_btn)
        attack_toolbar.addWidget(self.copy_attack_surface_selected_btn)
        attack_toolbar.addStretch(1)
        attack_layout.addLayout(attack_toolbar)
        self.attack_surface_table = QtWidgets.QTableWidget(0, 9)
        self._setup_table(self.attack_surface_table, ["Mode", "Surface", "Priority", "EA", "Function", "Roles", "Signals", "Evidence", "Next step"])
        attack_layout.addWidget(self.attack_surface_table, 1)
        self.tabs.addTab(attack_widget, "Attack Surface")

        findings_widget = QtWidgets.QWidget()
        findings_layout = QtWidgets.QVBoxLayout(findings_widget)
        findings_toolbar = QtWidgets.QHBoxLayout()
        self.copy_findings_btn = QtWidgets.QPushButton("Copy table")
        self.copy_findings_selected_btn = QtWidgets.QPushButton("Copy selected")
        self.mark_verified_btn = QtWidgets.QPushButton("Verified")
        self.mark_needs_proof_btn = QtWidgets.QPushButton("Needs proof")
        self.mark_false_positive_btn = QtWidgets.QPushButton("False positive")
        findings_toolbar.addWidget(self.copy_findings_btn)
        findings_toolbar.addWidget(self.copy_findings_selected_btn)
        findings_toolbar.addWidget(self.mark_verified_btn)
        findings_toolbar.addWidget(self.mark_needs_proof_btn)
        findings_toolbar.addWidget(self.mark_false_positive_btn)
        findings_toolbar.addStretch(1)
        findings_layout.addLayout(findings_toolbar)
        self.findings_table = QtWidgets.QTableWidget(0, 9)
        self._setup_table(self.findings_table, ["Severity", "Score", "Status", "EA", "Function", "Category", "Signal", "Evidence", "Confidence reason"])
        findings_layout.addWidget(self.findings_table, 1)
        self.tabs.addTab(findings_widget, "Findings")

        funcs_widget = QtWidgets.QWidget()
        funcs_layout = QtWidgets.QVBoxLayout(funcs_widget)
        funcs_toolbar = QtWidgets.QHBoxLayout()
        self.copy_functions_btn = QtWidgets.QPushButton("Copy table")
        self.copy_functions_selected_btn = QtWidgets.QPushButton("Copy selected")
        funcs_toolbar.addWidget(self.copy_functions_btn)
        funcs_toolbar.addWidget(self.copy_functions_selected_btn)
        funcs_toolbar.addStretch(1)
        funcs_layout.addLayout(funcs_toolbar)
        self.funcs_table = QtWidgets.QTableWidget(0, 9)
        self._setup_table(self.funcs_table, ["Score", "Status", "EA", "Function", "Roles", "Families", "IOCTLs", "Evidence", "Confidence reason"])
        funcs_layout.addWidget(self.funcs_table, 1)
        self.tabs.addTab(funcs_widget, "Functions")

        chains_widget = QtWidgets.QWidget()
        chains_layout = QtWidgets.QVBoxLayout(chains_widget)
        chains_toolbar = QtWidgets.QHBoxLayout()
        self.copy_chains_btn = QtWidgets.QPushButton("Copy table")
        self.copy_chains_selected_btn = QtWidgets.QPushButton("Copy selected")
        chains_toolbar.addWidget(self.copy_chains_btn)
        chains_toolbar.addWidget(self.copy_chains_selected_btn)
        chains_toolbar.addStretch(1)
        chains_layout.addLayout(chains_toolbar)
        self.chains_table = QtWidgets.QTableWidget(0, 12)
        self._setup_table(self.chains_table, ["Severity", "Confidence", "Type", "Status", "Entry EA", "Entry", "Target EA", "Target", "Primitive", "Access surface", "Evidence", "Confidence reason"])
        chains_layout.addWidget(self.chains_table, 1)
        self.tabs.addTab(chains_widget, "Primitive chains")

        graph_widget = QtWidgets.QWidget()
        graph_layout = QtWidgets.QVBoxLayout(graph_widget)
        graph_toolbar = QtWidgets.QHBoxLayout()
        self.copy_graph_btn = QtWidgets.QPushButton("Copy graph")
        graph_toolbar.addWidget(self.copy_graph_btn)
        graph_toolbar.addStretch(1)
        graph_layout.addLayout(graph_toolbar)
        self.chain_graph = QtWidgets.QTextBrowser()
        self.chain_graph.setOpenExternalLinks(False)
        graph_layout.addWidget(self.chain_graph, 1)
        self.tabs.addTab(graph_widget, "Chain graph")

        pseudo_widget = QtWidgets.QWidget()
        pseudo_layout = QtWidgets.QVBoxLayout(pseudo_widget)
        pseudo_toolbar = QtWidgets.QHBoxLayout()
        self.decompile_current_btn = QtWidgets.QPushButton("Decompile current")
        self.decompile_selected_btn = QtWidgets.QPushButton("Decompile selected finding")
        self.deep_pseudo_btn = QtWidgets.QPushButton("Deep pseudocode scan")
        self.generate_struct_btn = QtWidgets.QPushButton("Generate C struct")
        self.copy_pseudo_btn = QtWidgets.QPushButton("Copy tab")
        pseudo_toolbar.addWidget(self.decompile_current_btn)
        pseudo_toolbar.addWidget(self.decompile_selected_btn)
        pseudo_toolbar.addWidget(self.deep_pseudo_btn)
        pseudo_toolbar.addWidget(self.generate_struct_btn)
        pseudo_toolbar.addWidget(self.copy_pseudo_btn)
        pseudo_toolbar.addStretch(1)
        pseudo_layout.addLayout(pseudo_toolbar)
        self.pseudo_text = QtWidgets.QPlainTextEdit()
        self.pseudo_text.setLineWrapMode(QtWidgets.QPlainTextEdit.NoWrap)
        pseudo_layout.addWidget(self.pseudo_text, 1)
        self.tabs.addTab(pseudo_widget, "Pseudocode")

        correlation_widget = QtWidgets.QWidget()
        correlation_layout = QtWidgets.QVBoxLayout(correlation_widget)
        correlation_toolbar = QtWidgets.QHBoxLayout()
        self.copy_correlation_btn = QtWidgets.QPushButton("Copy table")
        self.copy_correlation_selected_btn = QtWidgets.QPushButton("Copy selected")
        correlation_toolbar.addWidget(self.copy_correlation_btn)
        correlation_toolbar.addWidget(self.copy_correlation_selected_btn)
        correlation_toolbar.addStretch(1)
        correlation_layout.addLayout(correlation_toolbar)
        self.correlation_table = QtWidgets.QTableWidget(0, 6)
        self._setup_table(self.correlation_table, ["Severity", "Confidence", "Family", "Top functions", "Review", "Confidence reason"])
        correlation_layout.addWidget(self.correlation_table, 1)
        self.tabs.addTab(correlation_widget, "Zero-day correlator")

        dynamic_widget = QtWidgets.QWidget()
        dynamic_layout = QtWidgets.QVBoxLayout(dynamic_widget)
        dynamic_form = QtWidgets.QFormLayout()
        self.device_path_edit = QtWidgets.QLineEdit()
        self.device_path_edit.setPlaceholderText(r"\\.\DeviceName")
        self.service_name_edit = QtWidgets.QLineEdit()
        self.service_name_edit.setPlaceholderText("ServiceName")
        self.driver_path_edit = QtWidgets.QLineEdit()
        self.driver_path_edit.setText(input_path())
        dynamic_form.addRow("Device path", self.device_path_edit)
        dynamic_form.addRow("Service name", self.service_name_edit)
        dynamic_form.addRow("Driver path", self.driver_path_edit)
        dynamic_layout.addLayout(dynamic_form)
        dynamic_toolbar = QtWidgets.QHBoxLayout()
        self.refresh_dynamic_btn = QtWidgets.QPushButton("Refresh proof plan")
        self.copy_dynamic_btn = QtWidgets.QPushButton("Copy tab")
        self.export_ps_probe_btn = QtWidgets.QPushButton("Export PowerShell probe")
        self.export_cpp_harness_btn = QtWidgets.QPushButton("Export C++ harness")
        self.export_dynamic_manifest_btn = QtWidgets.QPushButton("Export evidence manifest")
        dynamic_toolbar.addWidget(self.refresh_dynamic_btn)
        dynamic_toolbar.addWidget(self.copy_dynamic_btn)
        dynamic_toolbar.addWidget(self.export_ps_probe_btn)
        dynamic_toolbar.addWidget(self.export_cpp_harness_btn)
        dynamic_toolbar.addWidget(self.export_dynamic_manifest_btn)
        dynamic_toolbar.addStretch(1)
        dynamic_layout.addLayout(dynamic_toolbar)
        self.dynamic_text = QtWidgets.QPlainTextEdit()
        self.dynamic_text.setLineWrapMode(QtWidgets.QPlainTextEdit.NoWrap)
        dynamic_layout.addWidget(self.dynamic_text, 1)
        self.tabs.addTab(dynamic_widget, "Dynamic proof lab")

        proof_widget = QtWidgets.QWidget()
        proof_layout = QtWidgets.QVBoxLayout(proof_widget)
        proof_toolbar = QtWidgets.QHBoxLayout()
        self.proof_ioctl_combo = QtWidgets.QComboBox()
        self.proof_ioctl_combo.setMinimumWidth(320)
        self.refresh_proof_pack_btn = QtWidgets.QPushButton("Refresh proof pack")
        self.generate_proof_struct_btn = QtWidgets.QPushButton("Generate C struct")
        self.copy_proof_pack_btn = QtWidgets.QPushButton("Copy tab")
        self.export_proof_pack_btn = QtWidgets.QPushButton("Export proof pack")
        self.export_vs_project_btn = QtWidgets.QPushButton("Export VS project")
        proof_toolbar.addWidget(QtWidgets.QLabel("Focus IOCTL"))
        proof_toolbar.addWidget(self.proof_ioctl_combo)
        proof_toolbar.addWidget(self.refresh_proof_pack_btn)
        proof_toolbar.addWidget(self.generate_proof_struct_btn)
        proof_toolbar.addWidget(self.copy_proof_pack_btn)
        proof_toolbar.addWidget(self.export_proof_pack_btn)
        proof_toolbar.addWidget(self.export_vs_project_btn)
        proof_toolbar.addStretch(1)
        proof_layout.addLayout(proof_toolbar)
        self.proof_pack_text = QtWidgets.QPlainTextEdit()
        self.proof_pack_text.setLineWrapMode(QtWidgets.QPlainTextEdit.NoWrap)
        proof_layout.addWidget(self.proof_pack_text, 1)
        self.tabs.addTab(proof_widget, "Proof pack")

        fuzz_widget = QtWidgets.QWidget()
        fuzz_layout = QtWidgets.QVBoxLayout(fuzz_widget)
        fuzz_toolbar = QtWidgets.QHBoxLayout()
        self.refresh_fuzz_btn = QtWidgets.QPushButton("Refresh fuzz plan")
        self.copy_fuzz_btn = QtWidgets.QPushButton("Copy tab")
        self.export_fuzz_manifest_btn = QtWidgets.QPushButton("Export fuzz manifest")
        fuzz_toolbar.addWidget(self.refresh_fuzz_btn)
        fuzz_toolbar.addWidget(self.copy_fuzz_btn)
        fuzz_toolbar.addWidget(self.export_fuzz_manifest_btn)
        fuzz_toolbar.addStretch(1)
        fuzz_layout.addLayout(fuzz_toolbar)
        self.fuzz_text = QtWidgets.QPlainTextEdit()
        self.fuzz_text.setLineWrapMode(QtWidgets.QPlainTextEdit.NoWrap)
        fuzz_layout.addWidget(self.fuzz_text, 1)
        self.tabs.addTab(fuzz_widget, "Controlled fuzz")

        knowledge_widget = QtWidgets.QWidget()
        knowledge_layout = QtWidgets.QVBoxLayout(knowledge_widget)
        knowledge_toolbar = QtWidgets.QHBoxLayout()
        self.copy_knowledge_btn = QtWidgets.QPushButton("Copy tab")
        knowledge_toolbar.addWidget(self.copy_knowledge_btn)
        knowledge_toolbar.addStretch(1)
        knowledge_layout.addLayout(knowledge_toolbar)
        self.knowledge_text = QtWidgets.QTextBrowser()
        knowledge_layout.addWidget(self.knowledge_text, 1)
        self.tabs.addTab(knowledge_widget, "Knowledge")

        self.details = QtWidgets.QPlainTextEdit()
        self.details.setMaximumHeight(110)
        self.details.setReadOnly(True)
        root.addWidget(self.details)

        self.run_btn.clicked.connect(lambda: self.run_analysis(False))
        self.run_pseudo_btn.clicked.connect(lambda: self.run_analysis(True))
        self.full_scan_btn.clicked.connect(self.run_full_scan)
        self.fetch_lol_btn.clicked.connect(self.fetch_loldrivers)
        self.mode_combo.currentIndexChanged.connect(self.populate_attack_surface)
        self.export_json_btn.clicked.connect(self.export_json)
        self.export_md_btn.clicked.connect(self.export_markdown)
        self.export_full_report_btn.clicked.connect(self.export_full_report)
        self.decompile_current_btn.clicked.connect(self.decompile_current)
        self.decompile_selected_btn.clicked.connect(self.decompile_selected_finding)
        self.deep_pseudo_btn.clicked.connect(self.run_deep_pseudocode_scan)
        self.generate_struct_btn.clicked.connect(self.generate_c_struct_from_current)
        self.refresh_dynamic_btn.clicked.connect(self.populate_dynamic_plan)
        self.refresh_proof_pack_btn.clicked.connect(self.populate_proof_pack)
        self.generate_proof_struct_btn.clicked.connect(self.generate_c_struct_from_proof_focus)
        self.proof_ioctl_combo.currentIndexChanged.connect(self.populate_proof_pack_text_only)
        self.refresh_fuzz_btn.clicked.connect(self.populate_fuzz_plan)
        self.copy_dashboard_btn.clicked.connect(lambda: self.copy_text("Dashboard", self.dashboard.toPlainText()))
        self.copy_attack_surface_btn.clicked.connect(lambda: self.copy_table(self.attack_surface_table, False, "Attack Surface"))
        self.copy_attack_surface_selected_btn.clicked.connect(lambda: self.copy_table(self.attack_surface_table, True, "Selected attack surface"))
        self.copy_findings_btn.clicked.connect(lambda: self.copy_table(self.findings_table, False, "Findings"))
        self.copy_findings_selected_btn.clicked.connect(lambda: self.copy_table(self.findings_table, True, "Selected findings"))
        self.mark_verified_btn.clicked.connect(lambda: self.mark_selected_review_status("verified"))
        self.mark_needs_proof_btn.clicked.connect(lambda: self.mark_selected_review_status("needs proof"))
        self.mark_false_positive_btn.clicked.connect(lambda: self.mark_selected_review_status("false positive"))
        self.copy_functions_btn.clicked.connect(lambda: self.copy_table(self.funcs_table, False, "Functions"))
        self.copy_functions_selected_btn.clicked.connect(lambda: self.copy_table(self.funcs_table, True, "Selected functions"))
        self.copy_chains_btn.clicked.connect(lambda: self.copy_table(self.chains_table, False, "Primitive chains"))
        self.copy_chains_selected_btn.clicked.connect(lambda: self.copy_table(self.chains_table, True, "Selected primitive chains"))
        self.copy_graph_btn.clicked.connect(lambda: self.copy_text("Chain graph", self.chain_graph.toPlainText()))
        self.copy_pseudo_btn.clicked.connect(lambda: self.copy_text("Pseudocode", self.pseudo_text.toPlainText()))
        self.copy_correlation_btn.clicked.connect(lambda: self.copy_table(self.correlation_table, False, "Correlations"))
        self.copy_correlation_selected_btn.clicked.connect(lambda: self.copy_table(self.correlation_table, True, "Selected correlations"))
        self.copy_dynamic_btn.clicked.connect(lambda: self.copy_text("Dynamic proof plan", self.dynamic_text.toPlainText()))
        self.copy_proof_pack_btn.clicked.connect(lambda: self.copy_text("Proof pack", self.proof_pack_text.toPlainText()))
        self.copy_fuzz_btn.clicked.connect(lambda: self.copy_text("Controlled fuzz plan", self.fuzz_text.toPlainText()))
        self.copy_knowledge_btn.clicked.connect(lambda: self.copy_text("Knowledge", self.knowledge_text.toPlainText()))
        self.export_ps_probe_btn.clicked.connect(self.export_powershell_probe)
        self.export_cpp_harness_btn.clicked.connect(self.export_cpp_harness)
        self.export_dynamic_manifest_btn.clicked.connect(self.export_dynamic_manifest)
        self.export_proof_pack_btn.clicked.connect(self.export_proof_pack)
        self.export_vs_project_btn.clicked.connect(self.export_visual_studio_project)
        self.export_fuzz_manifest_btn.clicked.connect(self.export_fuzz_manifest)
        self.findings_table.cellDoubleClicked.connect(lambda row, _col: self.jump_from_table(self.findings_table, row, 3))
        self.attack_surface_table.cellDoubleClicked.connect(lambda row, _col: self.jump_from_table(self.attack_surface_table, row, 3))
        self.funcs_table.cellDoubleClicked.connect(lambda row, _col: self.jump_from_table(self.funcs_table, row, 2))
        self.chains_table.cellDoubleClicked.connect(lambda row, col: self.jump_from_table(self.chains_table, row, 6 if col >= 6 else 4))
        self.findings_table.itemSelectionChanged.connect(self.update_details_from_finding)
        self.funcs_table.itemSelectionChanged.connect(self.update_details_from_function)
        self.chains_table.itemSelectionChanged.connect(self.update_details_from_chain)
        self.correlation_table.itemSelectionChanged.connect(self.update_details_from_correlation)

        self.populate_knowledge()
        self.populate_dynamic_plan()
        self.populate_proof_pack()
        self.populate_fuzz_plan()
        self.update_dashboard()
        self.pseudo_highlighter = DragonPseudocodeHighlighter(self.pseudo_text.document())
        self.proof_highlighter = DragonPseudocodeHighlighter(self.proof_pack_text.document())
        self._apply_tooltips()

    def _apply_theme(self) -> None:
        self.setStyleSheet("""
QWidget#DragonReverseRoot {
    background: #f3f5f7;
    color: #1f2937;
    font-size: 12px;
}
QTabWidget::pane {
    border: 1px solid #cbd5e1;
    border-radius: 6px;
    background: #ffffff;
}
QTabBar::tab {
    background: #e8edf3;
    color: #334155;
    border: 1px solid #cbd5e1;
    border-bottom: none;
    padding: 7px 12px;
    margin-right: 2px;
    border-top-left-radius: 5px;
    border-top-right-radius: 5px;
}
QTabBar::tab:selected {
    background: #ffffff;
    color: #0f172a;
    border-top: 3px solid #2563eb;
    padding-top: 5px;
}
QPushButton {
    background: #ffffff;
    color: #1f2937;
    border: 1px solid #cbd5e1;
    border-radius: 5px;
    padding: 5px 10px;
}
QPushButton:hover {
    background: #f8fafc;
    border-color: #94a3b8;
}
QPushButton:pressed {
    background: #e2e8f0;
}
QPushButton[primary="true"] {
    background: #2563eb;
    color: #ffffff;
    border-color: #1d4ed8;
    font-weight: 600;
}
QPushButton[accent="true"] {
    background: #0f766e;
    color: #ffffff;
    border-color: #0f5f59;
    font-weight: 600;
}
QLabel#StatusLabel {
    background: #111827;
    color: #e5e7eb;
    border-radius: 5px;
    padding: 6px 8px;
}
QLabel[severityChip="true"] {
    border-radius: 5px;
    padding: 4px 8px;
    font-weight: 600;
}
QTableWidget {
    background: #ffffff;
    alternate-background-color: #f8fafc;
    color: #111827;
    gridline-color: #e2e8f0;
    border: 1px solid #cbd5e1;
    border-radius: 5px;
    selection-background-color: #bfdbfe;
    selection-color: #0f172a;
}
QHeaderView::section {
    background: #e8edf3;
    color: #0f172a;
    border: none;
    border-right: 1px solid #cbd5e1;
    border-bottom: 1px solid #cbd5e1;
    padding: 6px;
    font-weight: 600;
}
QPlainTextEdit, QTextBrowser, QLineEdit {
    background: #ffffff;
    color: #111827;
    border: 1px solid #cbd5e1;
    border-radius: 5px;
    padding: 6px;
    selection-background-color: #bfdbfe;
}
QLineEdit:focus, QPlainTextEdit:focus {
    border-color: #2563eb;
}
""")

    def _apply_tooltips(self) -> None:
        tooltips = {
            self.run_btn: "Lance l'analyse statique rapide : imports, strings, instructions, IOCTLs, familles de risques et corrélations.",
            self.run_pseudo_btn: "Analyse statique + pseudo-code Hex-Rays sur les fonctions les plus prioritaires. Plus précis, mais plus lent.",
            self.full_scan_btn: "Scan profond : analyse tout, décompile toutes les fonctions possibles, infère les rôles et propage la reachability IOCTL.",
            self.fetch_lol_btn: "Interroge l'API LOLDrivers et cherche une correspondance exacte SHA-256 avec le driver chargé.",
            self.export_json_btn: "Exporte les résultats d'analyse courants en JSON structuré.",
            self.export_md_btn: "Exporte un rapport Markdown lisible avec corrélations, findings et fonctions prioritaires.",
            self.export_full_report_btn: "Exporte un dossier complet de preuve en JSON ou TXT. Lance Full Scan automatiquement si nécessaire.",
            self.mode_combo: "Filtre réellement les familles de règles : Auto, Driver, Service, Hypervisor ou Universal.",
            self.copy_dashboard_btn: "Copie le résumé Dashboard dans le presse-papiers.",
            self.copy_attack_surface_btn: "Copie toutes les surfaces d'attaque regroupées par mode : IOCTL, RPC, pipes, COM, ALPC, hypercalls, VMBus et fichiers.",
            self.copy_attack_surface_selected_btn: "Copie uniquement les surfaces d'attaque sélectionnées.",
            self.copy_findings_btn: "Copie tout le tableau Findings au format TSV pour Intigriti/MSRC ou tableur.",
            self.copy_findings_selected_btn: "Copie uniquement les findings sélectionnés au format TSV.",
            self.mark_verified_btn: "Marque les lignes sélectionnées comme vérifiées manuellement.",
            self.mark_needs_proof_btn: "Marque les lignes sélectionnées comme hypothèse nécessitant une preuve dynamique ou manuelle.",
            self.mark_false_positive_btn: "Marque les lignes sélectionnées comme faux positif pour les exports et la revue.",
            self.copy_functions_btn: "Copie tout le tableau Functions avec rôles, familles, IOCTLs et evidence.",
            self.copy_functions_selected_btn: "Copie uniquement les fonctions sélectionnées.",
            self.copy_chains_btn: "Copie toutes les chaînes primitives : surface d'entrée, cible sensible, primitive, confidence et preuve à produire.",
            self.copy_chains_selected_btn: "Copie uniquement les chaînes primitives sélectionnées.",
            self.copy_graph_btn: "Copie la vue graphe des chaînes, avec les edges et la version DOT.",
            self.decompile_current_btn: "Décompile la fonction actuellement ouverte dans IDA et ajoute le profil Dragon Reverse.",
            self.decompile_selected_btn: "Décompile la fonction liée au finding sélectionné.",
            self.generate_struct_btn: "Génère une structure C depuis les offsets récupérés dans le pseudo-code de la fonction sélectionnée/courante.",
            self.copy_pseudo_btn: "Copie le pseudo-code affiché et son profil de revue.",
            self.copy_correlation_btn: "Copie toutes les corrélations zero-day au format TSV.",
            self.copy_correlation_selected_btn: "Copie uniquement les corrélations sélectionnées.",
            self.refresh_dynamic_btn: "Reconstruit le plan de preuve dynamique à partir des findings, rôles, IOCTLs et chemins device.",
            self.copy_dynamic_btn: "Copie le plan de preuve dynamique dans le presse-papiers.",
            self.export_ps_probe_btn: "Exporte un probe PowerShell non destructif : contexte, signature, service, ACL et matrice CreateFile. Aucun DeviceIoControl.",
            self.export_cpp_harness_btn: "Exporte un harness C++ contrôlé. DeviceIoControl reste désactivé sans flags explicites.",
            self.export_dynamic_manifest_btn: "Exporte un manifest JSON de preuve : cible, hypothèses, contrôles négatifs/positifs, IOCTLs et artefacts à collecter.",
            self.proof_ioctl_combo: "Choisit l'IOCTL précis à documenter dans le Proof Pack. Le rapport garde les autres IOCTLs comme contexte.",
            self.refresh_proof_pack_btn: "Reconstruit le rapport idéal MSRC/Intigriti : identité, accès low-priv, dispatch, IOCTLs et liens statiques vers sinks.",
            self.generate_proof_struct_btn: "Génère une structure C pour l'IOCTL focus à partir du meilleur lien statique du Proof Pack.",
            self.copy_proof_pack_btn: "Copie le Proof Pack complet dans le presse-papiers.",
            self.export_proof_pack_btn: "Exporte le Proof Pack en TXT ou JSON avec les hypothèses, limites et artefacts de preuve à collecter.",
            self.export_vs_project_btn: "Exporte un projet Visual Studio complet : harness C++, header des structures IOCTL, manifest JSON et README de reproduction.",
            self.refresh_fuzz_btn: "Reconstruit un plan de fuzz contrôlé sans exécution automatique. À utiliser seulement en VM/snapshot.",
            self.copy_fuzz_btn: "Copie le plan de fuzz contrôlé.",
            self.export_fuzz_manifest_btn: "Exporte un manifest JSON de fuzz contrôlé : IOCTLs, tailles, garde-fous et critères d'arrêt.",
            self.copy_knowledge_btn: "Copie la base de connaissances chargée : familles, signaux et hashes locaux connus."
        }
        for widget, text in tooltips.items():
            widget.setToolTip(text)
            widget.setStatusTip(text)
        self.deep_pseudo_btn.setToolTip("Lance une passe Hex-Rays profonde : sources utilisateur, sinks, guards, dispatch, CTL_CODE calculés, data-flow lite et champs de structure IOCTL.")
        self.deep_pseudo_btn.setStatusTip(self.deep_pseudo_btn.toolTip())
        self.device_path_edit.setToolTip("Chemin utilisateur du device, par exemple \\\\.\\NomDevice. Utilisé pour le plan dynamique et les probes.")
        self.service_name_edit.setToolTip("Nom du service Windows du driver. Utilisé pour lire HKLM\\SYSTEM\\CurrentControlSet\\Services\\Nom.")
        self.driver_path_edit.setToolTip("Chemin du fichier .sys analysé. Utilisé pour hash, signature et rapport de preuve.")

    def _set_analysis_busy(self, busy: bool, status: str | None = None) -> None:
        self.analysis_running = busy
        for name in (
            "run_btn", "run_pseudo_btn", "full_scan_btn", "fetch_lol_btn",
            "export_json_btn", "export_md_btn", "export_full_report_btn",
            "decompile_current_btn", "decompile_selected_btn", "deep_pseudo_btn",
            "refresh_proof_pack_btn", "export_proof_pack_btn", "export_vs_project_btn",
            "mode_combo"
        ):
            button = getattr(self, name, None)
            if button is not None:
                button.setEnabled(not busy)
        if status:
            self.status.setText(status)
        QtWidgets.QApplication.processEvents()

    def _severity_chip(self, severity: str) -> QtWidgets.QLabel:
        colors = SEVERITY_COLORS.get(severity, SEVERITY_COLORS["Info"])
        label = QtWidgets.QLabel(severity)
        label.setProperty("severityChip", True)
        label.setStyleSheet(
            "background: %s; color: %s; border: 1px solid %s;" %
            (colors["bg"], colors["fg"], colors["border"])
        )
        return label

    def _setup_table(self, table: QtWidgets.QTableWidget, headers: list[str]) -> None:
        table.setHorizontalHeaderLabels(headers)
        table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        table.setSelectionMode(QtWidgets.QAbstractItemView.ExtendedSelection)
        table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        table.verticalHeader().setVisible(False)
        table.horizontalHeader().setStretchLastSection(True)
        table.setAlternatingRowColors(True)
        table.setShowGrid(True)

    def _severity_colors(self, severity: str) -> dict[str, str]:
        return SEVERITY_COLORS.get(severity, SEVERITY_COLORS["Info"])

    def _style_severity_item(self, item: QtWidgets.QTableWidgetItem, severity: str) -> None:
        colors = self._severity_colors(severity)
        item.setForeground(QtGui.QBrush(QtGui.QColor(colors["fg"])))
        item.setBackground(QtGui.QBrush(QtGui.QColor(colors["bg"])))
        font = item.font()
        font.setBold(True)
        item.setFont(font)

    def _tint_row(self, table: QtWidgets.QTableWidget, row: int, severity: str, strong_cols: set[int] | None = None) -> None:
        colors = self._severity_colors(severity)
        strong_cols = strong_cols or set()
        for col in range(table.columnCount()):
            item = table.item(row, col)
            if not item:
                continue
            if col in strong_cols:
                self._style_severity_item(item, severity)
            else:
                item.setBackground(QtGui.QBrush(QtGui.QColor(colors["soft"])))
                if severity in {"Critical", "High"}:
                    item.setForeground(QtGui.QBrush(QtGui.QColor("#111827")))

    def _score_severity(self, score: Any) -> str:
        try:
            return severity_from_score(int(score))
        except Exception:
            return "Info"

    def copy_text(self, label: str, text: str) -> None:
        QtWidgets.QApplication.clipboard().setText(text or "")
        self.status.setText("Copied %s to clipboard." % label)

    def copy_table(self, table: QtWidgets.QTableWidget, selected_only: bool, label: str) -> None:
        text = self._table_to_tsv(table, selected_only)
        QtWidgets.QApplication.clipboard().setText(text)
        row_count = max(0, len(text.splitlines()) - 1) if text else 0
        self.status.setText("Copied %s to clipboard (%d rows)." % (label, row_count))

    def mark_selected_review_status(self, status: str) -> None:
        table, status_col = self._active_review_table()
        if table is None:
            self.status.setText("Open Findings, Functions, or Primitive chains before marking review status.")
            return
        rows = [idx.row() for idx in table.selectionModel().selectedRows()]
        if not rows and table.currentRow() >= 0:
            rows = [table.currentRow()]
        if not rows:
            self.status.setText("No selected rows to mark.")
            return
        for row in sorted(set(rows)):
            item = table.item(row, status_col)
            if item is None:
                item = QtWidgets.QTableWidgetItem(status)
                table.setItem(row, status_col, item)
            item.setText(status)
            self._apply_status_to_model(table, row, status)
        self.status.setText("Marked %d row(s) as %s." % (len(set(rows)), status))
        self.populate_dynamic_plan()
        self.populate_proof_pack()
        self.update_dashboard()

    def _active_review_table(self) -> tuple[QtWidgets.QTableWidget | None, int]:
        idx = self.tabs.currentIndex()
        if idx == 1:
            return self.findings_table, 2
        if idx == 2:
            return self.funcs_table, 1
        if idx == 3:
            return self.chains_table, 3
        for table, col in ((self.findings_table, 2), (self.funcs_table, 1), (self.chains_table, 3)):
            if table.selectionModel().selectedRows():
                return table, col
        return None, -1

    def _apply_status_to_model(self, table: QtWidgets.QTableWidget, row: int, status: str) -> None:
        if table is self.findings_table and row < len(self.analyzer.findings):
            self.analyzer.findings[row].review_status = status
        elif table is self.funcs_table and row < len(self.analyzer.functions):
            self.analyzer.functions[row].review_status = status
        elif table is self.chains_table and row < len(self.analyzer.primitive_chains):
            self.analyzer.primitive_chains[row].review_status = status

    def _table_to_tsv(self, table: QtWidgets.QTableWidget, selected_only: bool = False) -> str:
        headers = []
        for col in range(table.columnCount()):
            header = table.horizontalHeaderItem(col)
            headers.append(header.text() if header else "Column%d" % col)
        if selected_only:
            selected = sorted({idx.row() for idx in table.selectionModel().selectedRows()})
            if selected:
                rows = selected
            elif table.currentRow() >= 0:
                rows = [table.currentRow()]
            else:
                rows = []
        else:
            rows = list(range(table.rowCount()))
        out = ["\t".join(headers)]
        for row in rows:
            values = []
            for col in range(table.columnCount()):
                item = table.item(row, col)
                value = item.text() if item else ""
                values.append(value.replace("\t", " ").replace("\r", " ").replace("\n", " "))
            out.append("\t".join(values))
        return "\n".join(out)

    def run_analysis(self, include_pseudocode: bool) -> None:
        if self.analysis_running:
            self.status.setText("Analysis already running; wait for the current scan to finish.")
            return
        self._set_analysis_busy(True, "Running analysis...")
        try:
            self.analyzer = DragonAnalyzer(self.rules, self.current_analysis_mode())
            self.analyzer.run(include_pseudocode=include_pseudocode, pseudocode_limit=25)
            self.populate_all()
            self.status.setText("Analysis complete: %d findings, %d functions, %d correlations." % (
                len(self.analyzer.findings), len(self.analyzer.functions), len(self.analyzer.correlations)))
        except Exception:
            self.status.setText("Analysis failed. See output window.")
            ida_kernwin.msg("[DragonReverse] Analysis failed\n%s\n" % traceback.format_exc())
        finally:
            self._set_analysis_busy(False)

    def run_full_scan(self) -> None:
        if self.analysis_running:
            self.status.setText("Analysis already running; wait for the current scan to finish.")
            return
        self._set_analysis_busy(True, "Running Full Scan: static + all-function pseudocode + reachability...")
        try:
            self.analyzer = DragonAnalyzer(self.rules, self.current_analysis_mode())
            self.analyzer.run(include_pseudocode=True, full_scan=True)
            self.populate_all()
            self.status.setText(
                "Full Scan complete: %d findings, %d functions, %d correlations, %d pseudocode bodies, %d decompile failures." % (
                    len(self.analyzer.findings),
                    len(self.analyzer.functions),
                    len(self.analyzer.correlations),
                    len(self.analyzer.pseudocode_by_ea),
                    len(self.analyzer.pseudocode_failures)))
        except Exception:
            self.status.setText("Full Scan failed. See output window.")
            ida_kernwin.msg("[DragonReverse] Full Scan failed\n%s\n" % traceback.format_exc())
        finally:
            self._set_analysis_busy(False)

    def run_deep_pseudocode_scan(self) -> None:
        if self.analysis_running:
            self.status.setText("Analysis already running; wait for the current scan to finish.")
            return
        self._set_analysis_busy(True, "Running Deep Pseudocode Scan: Hex-Rays facts + dispatcher assignments + proof hypotheses...")
        try:
            self.analyzer = DragonAnalyzer(self.rules, self.current_analysis_mode())
            self.analyzer.run(include_pseudocode=True, full_scan=True)
            self.populate_all()
            self.pseudo_text.setPlainText(self.pseudocode_deep_report())
            self.tabs.setCurrentWidget(self.pseudo_text.parentWidget())
            self.status.setText(
                "Deep Pseudocode Scan complete: %d findings, %d chains, %d pseudocode bodies." % (
                    len(self.analyzer.findings),
                    len(self.analyzer.primitive_chains),
                    len(self.analyzer.pseudocode_by_ea)))
        except Exception:
            self.status.setText("Deep Pseudocode Scan failed. See output window.")
            ida_kernwin.msg("[DragonReverse] Deep Pseudocode Scan failed\n%s\n" % traceback.format_exc())
        finally:
            self._set_analysis_busy(False)

    def populate_all(self) -> None:
        self.populate_findings()
        self.populate_functions()
        self.populate_chains()
        self.populate_chain_graph()
        self.populate_attack_surface()
        self.populate_correlations()
        self.populate_dynamic_plan()
        self.populate_proof_pack()
        self.populate_fuzz_plan()
        self.update_dashboard()

    def current_analysis_mode(self) -> str:
        try:
            data = self.mode_combo.currentData()
            if data:
                return str(data)
        except Exception:
            pass
        return "auto"

    def populate_findings(self) -> None:
        self.findings_table.setRowCount(0)
        for finding in self.analyzer.findings:
            row = self.findings_table.rowCount()
            self.findings_table.insertRow(row)
            for col, value in enumerate(finding.as_row()):
                item = QtWidgets.QTableWidgetItem(value)
                item.setData(USER_ROLE, qt_ea_data(finding.ea))
                self.findings_table.setItem(row, col, item)
            self._tint_row(self.findings_table, row, finding.severity, {0})
        self.findings_table.resizeColumnsToContents()

    def populate_functions(self) -> None:
        self.funcs_table.setRowCount(0)
        for fn in self.analyzer.functions:
            ioctl_text = ", ".join("%s %s %s" % (i["hex"], i["access"], i["method"]) for i in fn.ioctls[:5])
            row_values = [
                str(fn.score),
                fn.review_status,
                ea_text(fn.ea),
                fn.name,
                ", ".join(sorted(fn.roles)),
                ", ".join(sorted(fn.families)),
                ioctl_text,
                ", ".join(sorted(set(fn.evidence)))[:260],
                fn.confidence_reason
            ]
            row = self.funcs_table.rowCount()
            self.funcs_table.insertRow(row)
            for col, value in enumerate(row_values):
                item = QtWidgets.QTableWidgetItem(value)
                item.setData(USER_ROLE, qt_ea_data(fn.ea))
                self.funcs_table.setItem(row, col, item)
            self._tint_row(self.funcs_table, row, self._score_severity(fn.score), {0})
        self.funcs_table.resizeColumnsToContents()

    def populate_chains(self) -> None:
        self.chains_table.setRowCount(0)
        for chain in self.analyzer.primitive_chains:
            row = self.chains_table.rowCount()
            self.chains_table.insertRow(row)
            for col, value in enumerate(chain.as_row()):
                item = QtWidgets.QTableWidgetItem(value)
                item.setData(USER_ROLE, qt_ea_data(chain.target_ea if col >= 6 else chain.entry_ea))
                self.chains_table.setItem(row, col, item)
            self._tint_row(self.chains_table, row, chain.severity, {0, 1})
        self.chains_table.resizeColumnsToContents()

    def populate_attack_surface(self) -> None:
        if not hasattr(self, "attack_surface_table"):
            return
        rows = self.attack_surface_rows()
        self.attack_surface_table.setRowCount(0)
        for row_data in rows:
            row = self.attack_surface_table.rowCount()
            self.attack_surface_table.insertRow(row)
            values = [
                row_data.get("mode", ""),
                row_data.get("surface", ""),
                str(row_data.get("priority", "")),
                ea_text(row_data.get("ea", idc.BADADDR)),
                row_data.get("function", ""),
                row_data.get("roles", ""),
                row_data.get("signals", ""),
                row_data.get("evidence", ""),
                row_data.get("next_step", ""),
            ]
            for col, value in enumerate(values):
                item = QtWidgets.QTableWidgetItem(value)
                item.setData(USER_ROLE, qt_ea_data(row_data.get("ea", idc.BADADDR)))
                self.attack_surface_table.setItem(row, col, item)
            self._tint_row(self.attack_surface_table, row, self._score_severity(int(row_data.get("priority", 0) or 0)), {2})
        self.attack_surface_table.resizeColumnsToContents()

    def attack_surface_rows(self) -> list[dict[str, Any]]:
        selected_mode = self.current_analysis_mode()
        rows: list[dict[str, Any]] = []
        for fn in self.analyzer.functions:
            for surface in self._surfaces_for_function(fn):
                if selected_mode not in {"auto", "universal"} and surface["mode"] not in {selected_mode, "universal"}:
                    continue
                row = dict(surface)
                row.update({
                    "priority": max(fn.score, surface.get("base_priority", 0)),
                    "ea": fn.ea,
                    "function": fn.name,
                    "roles": ", ".join(sorted(fn.roles)),
                    "signals": self._surface_signals(fn, surface["surface"]),
                    "evidence": ", ".join(sorted(set(fn.evidence)))[:260],
                })
                rows.append(row)
        rows.extend(self._string_attack_surface_rows(selected_mode))
        rows.sort(key=lambda item: (int(item.get("priority", 0) or 0), str(item.get("surface", ""))), reverse=True)
        return rows[:250]

    def _surfaces_for_function(self, fn: FunctionSummary) -> list[dict[str, Any]]:
        roles = set(fn.roles)
        families = set(fn.families)
        facts = fn.pseudocode_facts or {}
        pool = set(fn.calls) | set(fn.strings) | set(fn.mnemonics) | set(fn.evidence)
        for key, values in facts.items():
            pool.add(key)
            pool.update(values or [])
        surfaces: list[dict[str, Any]] = []

        def has_role(name: str) -> bool:
            return name in roles

        def has_family(name: str) -> bool:
            return name in families

        def any_signal(tokens: Iterable[str]) -> bool:
            return any(any(self.analyzer._signal_matches(token, item) for item in pool) for token in tokens)

        def add(mode: str, surface: str, priority: int, next_step: str) -> None:
            if not any(item["surface"] == surface and item["mode"] == mode for item in surfaces):
                surfaces.append({"mode": mode, "surface": surface, "base_priority": priority, "next_step": next_step})

        if fn.ioctls or has_role("IOCTL dispatcher") or has_family("file_any_access_ioctl"):
            add("driver", "IOCTL dispatcher", 70, "Decode IOCTLs, recover switch/case branches, then map input fields to sensitive sinks.")
        if has_role("Device ACL / namespace exposure") or has_family("weak_device_acl"):
            add("driver", "Device object / DOS link", 58, "Recover device name, symbolic link, SDDL/default DACL, and low-privileged CreateFile matrix.")
        if has_role("RPC interface surface") or has_family("rpc_interface_surface") or any_signal(PSEUDOCODE_FACT_GROUPS["rpc_surface"]):
            add("service", "RPC interface", 72, "Extract UUID/interface pointer, endpoint/protseq, opnums, auth callback, and impersonation behavior.")
        if has_role("Named pipe IPC surface") or has_family("named_pipe_surface") or any_signal(PSEUDOCODE_FACT_GROUPS["named_pipe_surface"]):
            add("service", "Named pipe IPC", 68, "Extract pipe name and SDDL; test low-privileged connect/write and message parser trust.")
        if has_role("COM/DCOM activation surface") or has_family("com_dcom_surface") or any_signal(PSEUDOCODE_FACT_GROUPS["com_surface"]):
            add("service", "COM/DCOM class", 64, "Recover CLSID/AppID, launch/access permissions, authn level, impersonation level, and privileged methods.")
        if has_role("ALPC/named port boundary") or has_family("alpc_service_surface") or any_signal(PSEUDOCODE_FACT_GROUPS["alpc_surface"]):
            add("service", "ALPC / named port", 66, "Recover port name, security descriptor, message layout, security QoS, and server authorization.")
        if has_role("Impersonation boundary") or has_family("impersonation_boundary") or any_signal(PSEUDOCODE_FACT_GROUPS["impersonation_sinks"]):
            add("service", "Impersonation boundary", 74, "Verify impersonation level, token identity, revert paths, and privileged action after impersonation.")
        if has_role("Privileged file/symlink operation") or has_family("privileged_file_op") or any_signal(PSEUDOCODE_FACT_GROUPS["file_sinks"]):
            add("service", "Privileged file/symlink operation", 70, "Trace caller-controlled paths into SYSTEM file operations; check reparse/hardlink/final-path defenses.")
        if has_role("Hypervisor hypercall surface") or has_family("hypercall_surface") or fn.mnemonics & {"vmcall", "vmmcall"} or any_signal(PSEUDOCODE_FACT_GROUPS["hypercall_sinks"]):
            add("hypervisor", "Hypercall surface", 78, "Map hypercall numbers and guest-controlled register/buffer inputs; recover struct sizes and privilege gates.")
        if has_role("VMBus packet parser") or has_family("vmbus_packet_surface") or any_signal(PSEUDOCODE_FACT_GROUPS["vmbus_surface"]):
            add("hypervisor", "VMBus / virtual device parser", 76, "Recover packet header, message type switch, ring-buffer bounds, and integer arithmetic guards.")
        if has_role("TOCTOU user-buffer race candidate") or has_family("toctou_user_buffer") or facts.get("toctou_candidates"):
            add("universal", "TOCTOU user-buffer reread", 72, "Confirm check/use split: copy the field once, compare against later reread from original user-controlled storage.")
        return surfaces

    def _surface_signals(self, fn: FunctionSummary, surface: str) -> str:
        facts = fn.pseudocode_facts or {}
        pieces: list[str] = []
        surface_map = {
            "RPC interface": "rpc_surface",
            "Named pipe IPC": "named_pipe_surface",
            "COM/DCOM class": "com_surface",
            "ALPC / named port": "alpc_surface",
            "Impersonation boundary": "impersonation_sinks",
            "Privileged file/symlink operation": "file_sinks",
            "Hypercall surface": "hypercall_sinks",
            "VMBus / virtual device parser": "vmbus_surface",
            "TOCTOU user-buffer reread": "toctou_candidates",
        }
        key = surface_map.get(surface)
        if key and facts.get(key):
            pieces.extend(facts.get(key, [])[:6])
        if surface == "IOCTL dispatcher" and fn.ioctls:
            pieces.extend("%s %s %s" % (item.get("hex", ""), item.get("access", ""), item.get("method", "")) for item in fn.ioctls[:5])
        if not pieces:
            pieces.extend(sorted((set(fn.calls) | set(fn.mnemonics)) & self._surface_token_set(surface))[:8])
        return ", ".join(pieces)[:240]

    def _surface_token_set(self, surface: str) -> set[str]:
        mapping = {
            "RPC interface": "rpc_surface",
            "Named pipe IPC": "named_pipe_surface",
            "COM/DCOM class": "com_surface",
            "ALPC / named port": "alpc_surface",
            "Impersonation boundary": "impersonation_sinks",
            "Privileged file/symlink operation": "file_sinks",
            "Hypercall surface": "hypercall_sinks",
            "VMBus / virtual device parser": "vmbus_surface",
        }
        key = mapping.get(surface, "")
        return set(PSEUDOCODE_FACT_GROUPS.get(key, []))

    def _string_attack_surface_rows(self, selected_mode: str) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        seen: set[str] = set()
        for ea, text in self.analyzer.critical_strings:
            lower = text.lower()
            row = None
            if ("\\pipe\\" in lower or "\\\\.\\pipe\\" in lower) and selected_mode in {"auto", "universal", "service"}:
                row = ("service", "Named pipe string", 42, "Use xrefs to find CreateNamedPipe/ConnectNamedPipe and recover SDDL.", text)
            elif re.search(r"\{?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}?", text) and selected_mode in {"auto", "universal", "service"}:
                row = ("service", "UUID/CLSID string", 38, "Use xrefs to classify as RPC interface UUID, COM CLSID/AppID, or unrelated GUID.", text)
            elif ("\\rpc control\\" in lower or "alpc" in lower) and selected_mode in {"auto", "universal", "service"}:
                row = ("service", "ALPC/RPC Control string", 40, "Use xrefs to recover named port endpoint and security descriptor.", text)
            elif ("vmbus" in lower or "vmbchannel" in lower or "hypercall" in lower) and selected_mode in {"auto", "universal", "hypervisor"}:
                row = ("hypervisor", "Virtualization string", 44, "Use xrefs to find packet parser or hypercall dispatch path.", text)
            if row:
                key = "%s:%s" % (row[1], row[4])
                if key in seen:
                    continue
                seen.add(key)
                rows.append({
                    "mode": row[0],
                    "surface": row[1],
                    "priority": row[2],
                    "ea": ea,
                    "function": "",
                    "roles": "",
                    "signals": row[4][:160],
                    "evidence": "critical string",
                    "next_step": row[3],
                })
        return rows[:80]

    def populate_chain_graph(self) -> None:
        self.chain_graph.setHtml(self.chain_graph_html())

    def chain_graph_html(self) -> str:
        chains = self.analyzer.primitive_chains[:80]
        if not chains:
            return "<h2>Chain graph</h2><p>No primitive chains yet. Run Full Scan or Deep pseudocode scan.</p>"
        colors = {
            "strict": "#166534",
            "pseudocode": "#1d4ed8",
            "profile_seed": "#92400e"
        }
        html = ["<h2>Chain graph</h2>"]
        html.append("<p>Green=strict, blue=pseudocode-assisted, amber=profile seed. Pseudocode/profile-seed chains are triage hypotheses until dynamic reachability and exact branch/data-flow are proven.</p>")
        html.append("<div style='font-family: Segoe UI, sans-serif;'>")
        for chain in chains:
            color = colors.get(chain.chain_type, "#334155")
            html.append(
                "<div style='margin:6px 0;padding:7px;border-left:5px solid %s;background:#f8fafc;'>"
                "<b>%s</b> <span style='color:%s'>--[%s/%d/%s]--></span> <b>%s</b>"
                "<br><code>%s</code><br><small>%s</small></div>" % (
                    color,
                    self._html(chain.entry),
                    color,
                    self._html(chain.primitive),
                    chain.confidence,
                    self._html(chain.chain_type),
                    self._html(chain.target),
                    self._html(chain.access_surface),
                    self._html(chain.confidence_reason or chain.proof_focus)
                )
            )
        html.append("</div>")
        html.append("<h3>DOT export</h3><pre>%s</pre>" % self._html(self.chain_graph_dot(chains)))
        return "\n".join(html)

    def chain_graph_dot(self, chains: list[PrimitiveChain] | None = None) -> str:
        chains = chains if chains is not None else self.analyzer.primitive_chains
        lines = ["digraph DragonReverseChains {", "  rankdir=LR;", "  node [shape=box, style=rounded];"]
        for chain in chains:
            color = {"strict": "green4", "pseudocode": "blue4", "profile_seed": "orange3"}.get(chain.chain_type, "gray30")
            label = "%s\\nconf=%d type=%s" % (chain.primitive.replace('"', "'"), chain.confidence, chain.chain_type)
            lines.append('  "%s" -> "%s" [label="%s", color="%s"];' % (
                chain.entry.replace('"', "'"),
                chain.target.replace('"', "'"),
                label,
                color
            ))
        lines.append("}")
        return "\n".join(lines)

    def populate_correlations(self) -> None:
        self.correlation_table.setRowCount(0)
        for row_data in self.analyzer.correlations:
            top = ", ".join("%s:%d [%s]" % (
                fn["name"],
                fn["score"],
                ",".join(fn.get("roles", [])[:2])) for fn in row_data.get("functions", [])[:5])
            row_values = [
                row_data.get("severity", ""),
                str(row_data.get("confidence", "")),
                row_data.get("name", ""),
                top,
                row_data.get("review", ""),
                row_data.get("confidence_reason", "")
            ]
            row = self.correlation_table.rowCount()
            self.correlation_table.insertRow(row)
            for col, value in enumerate(row_values):
                item = QtWidgets.QTableWidgetItem(str(value))
                item.setData(USER_ROLE, row)
                self.correlation_table.setItem(row, col, item)
            self._tint_row(self.correlation_table, row, str(row_data.get("severity", "Info")), {0, 1})
        self.correlation_table.resizeColumnsToContents()

    def pseudocode_deep_report(self) -> str:
        lines = [
            "Dragon Reverse Deep Pseudocode Scan",
            "",
            "Target",
            "  File: %s" % (self.analyzer.meta or {}).get("file", input_filename()),
            "  SHA256: %s" % (self.analyzer.meta or {}).get("sha256", input_sha256()),
            "  Pseudocode bodies: %d" % len(self.analyzer.pseudocode_by_ea),
            "  Decompile failures: %d" % len(self.analyzer.pseudocode_failures),
            "",
            "What changed versus raw token scanning",
            "  - memcpy/memmove alone is treated as low-value noise unless a user buffer or length field is visible.",
            "  - ZwOpenKey alone is treated as registry access, not registry write impact.",
            "  - MajorFunction[IRP_MJ_DEVICE_CONTROL] assignments are used to recover dispatcher targets.",
            "  - Primitive chains can use pseudocode IOCTL surfaces even when strict IOCTL constants are not decoded.",
            "  - CTL_CODE(...) and simple bitwise IOCTL expressions are decoded when constants are hidden behind light arithmetic.",
            "  - IOCTL buffer structure fields are suggested from SystemBuffer/Type3InputBuffer aliases and offset accesses.",
            "  - chain_type=pseudocode is a strong review path, not final proof.",
            "  - no-nearby-guard-in-pseudocode-window means no nearby guard token in decompiled text, not proof that validation is absent.",
            "  - Scores and confidence values rank triage priority; they are not bounty confirmations.",
            ""
        ]
        dispatchers = [fn for fn in self.analyzer.functions if "IOCTL dispatcher" in fn.roles]
        if dispatchers:
            lines.append("Recovered dispatcher candidates")
            for fn in dispatchers[:20]:
                lines.append("  - %s %s score=%d evidence=%s" % (
                    ea_text(fn.ea), fn.name, fn.score,
                    ", ".join([e for e in fn.evidence if "dispatch" in e or "pseudo-ioctl" in e][:6]) or "role inference"))
        else:
            lines.append("Recovered dispatcher candidates")
            lines.append("  - None recovered yet. Inspect DriverEntry/device setup pseudocode for MajorFunction[14] assignments.")

        lines += ["", "Top pseudocode hypotheses"]
        ranked = [
            fn for fn in self.analyzer.functions
            if fn.pseudocode_facts and (self.analyzer._facts_have_sensitive_signal(fn.pseudocode_facts) or fn.pseudocode_facts.get("dispatch_assignments"))
        ]
        ranked.sort(key=lambda fn: (self.analyzer._pseudocode_risk_score(fn, fn.pseudocode_facts), fn.score), reverse=True)
        if ranked:
            for fn in ranked[:30]:
                facts = fn.pseudocode_facts
                lines.append("  - %s %s score=%d pseudo_risk=%d roles=%s" % (
                    ea_text(fn.ea),
                    fn.name,
                    fn.score,
                    self.analyzer._pseudocode_risk_score(fn, facts),
                    ", ".join(sorted(fn.roles)) or "none"))
                lines.append("    facts: %s" % self.analyzer._pseudocode_fact_evidence(facts))
                if fn.proof_notes:
                    lines.append("    proof: %s" % " | ".join(fn.proof_notes[:4]))
        else:
            lines.append("  - No high-value pseudocode hypothesis. This usually means the dispatcher was optimized or type info is missing.")

        lines += ["", "Primitive chains"]
        if self.analyzer.primitive_chains:
            for chain in self.analyzer.primitive_chains[:25]:
                lines.append("  - [%s/%d] %s -> %s | %s | surface=%s" % (
                    chain.severity, chain.confidence, chain.entry, chain.target, chain.primitive, chain.access_surface))
                lines.append("    proof: %s" % chain.proof_focus)
        else:
            lines.append("  - No chain yet. Prioritize recovered dispatchers and manually follow calls into the top pseudocode hypotheses.")

        lines += ["", "False-positive suppressions"]
        suppressed = []
        for fn in self.analyzer.functions:
            for evidence in fn.evidence:
                if evidence.startswith("suppressed-") or evidence == "registry-open-only-not-write":
                    suppressed.append("%s %s: %s" % (ea_text(fn.ea), fn.name, evidence))
        if suppressed:
            lines.extend("  - " + item for item in suppressed[:40])
        else:
            lines.append("  - No suppressions recorded.")

        lines += [
            "",
            "Manual next steps",
            "  1. Open the recovered dispatcher and rename the IOCTL code variable.",
            "  2. For each chain, trace buffer pointer + length together into the sink.",
            "  3. Check whether guards dominate every sink path, not only one branch.",
            "  4. Use Proof Pack and Dynamic Proof Lab for non-destructive reachability and CreateFile evidence before any active IOCTL test."
        ]
        return "\n".join(lines)

    def populate_dynamic_plan(self) -> None:
        if not self.service_name_edit.text().strip():
            guessed_service = os.path.splitext(input_filename())[0]
            self.service_name_edit.setText(guessed_service)
        if not self.driver_path_edit.text().strip():
            self.driver_path_edit.setText(input_path())
        if not self.device_path_edit.text().strip():
            guesses = self._device_path_guesses()
            if guesses:
                self.device_path_edit.setText(guesses[0])
        self.dynamic_text.setPlainText(self.dynamic_plan_text())

    def populate_proof_pack(self) -> None:
        self._refresh_proof_ioctl_combo()
        self.populate_proof_pack_text_only()

    def populate_proof_pack_text_only(self, *_args: Any) -> None:
        self.proof_pack_text.setPlainText(self.proof_pack_text_report())

    def generate_c_struct_from_current(self) -> None:
        summary = self._selected_summary_for_struct() or self._function_summary_for_ea(ida_kernwin.get_screen_ea())
        if not summary:
            self.pseudo_text.setPlainText("No function selected for C struct generation.")
            self.tabs.setCurrentWidget(self.pseudo_text.parentWidget())
            return
        if not summary.pseudocode_facts.get("ioctl_struct_fields"):
            text = self.analyzer.decompile_function(summary.ea)
            if text and not text.startswith("Decompile failed"):
                facts = self.analyzer._pseudocode_facts(text)
                summary.pseudocode_facts = facts
                summary.proof_notes = self.analyzer._pseudocode_proof_notes(facts)
        fields = summary.pseudocode_facts.get("ioctl_struct_fields") or []
        struct_text = self._c_struct_from_fields(fields, "%s_IOCTL_REQUEST" % self._safe_c_ident(summary.name).upper())
        self.pseudo_text.setPlainText(struct_text)
        self.tabs.setCurrentWidget(self.pseudo_text.parentWidget())
        self.status.setText("Generated C struct for %s (%d field candidates)." % (summary.name, len(fields)))

    def generate_c_struct_from_proof_focus(self) -> None:
        focus = self._selected_or_top_ioctl()
        mapping = self._ioctl_static_map(focus) if focus else {}
        fields: list[str] = []
        name = "DRAGON_IOCTL_REQUEST"
        for link in mapping.get("links", []) if mapping else []:
            fields = link.get("struct_fields", []) or []
            if fields:
                name = "%s_IOCTL_REQUEST" % self._safe_c_ident(str(link.get("target", "DRAGON"))).upper()
                break
        if not fields and mapping.get("entry"):
            entry = self._function_by_ea(int(mapping["entry"].get("ea", idc.BADADDR)))
            if entry:
                fields = entry.pseudocode_facts.get("ioctl_struct_fields") or []
                name = "%s_IOCTL_REQUEST" % self._safe_c_ident(entry.name).upper()
        struct_text = self._c_struct_from_fields(fields, name)
        self.proof_pack_text.setPlainText(self.proof_pack_text_report() + "\n\nGenerated C Struct\n\n" + struct_text)
        self.tabs.setCurrentWidget(self.proof_pack_text.parentWidget())
        self.status.setText("Generated Proof Pack C struct (%d field candidates)." % len(fields))

    def _selected_summary_for_struct(self) -> FunctionSummary | None:
        if self.funcs_table.selectionModel().selectedRows():
            row = self.funcs_table.selectionModel().selectedRows()[0].row()
            if row < len(self.analyzer.functions):
                return self.analyzer.functions[row]
        if self.findings_table.selectionModel().selectedRows():
            row = self.findings_table.selectionModel().selectedRows()[0].row()
            if row < len(self.analyzer.findings):
                return self._function_summary_for_ea(self.analyzer.findings[row].ea)
        if self.chains_table.selectionModel().selectedRows():
            row = self.chains_table.selectionModel().selectedRows()[0].row()
            if row < len(self.analyzer.primitive_chains):
                return self._function_summary_for_ea(self.analyzer.primitive_chains[row].target_ea)
        return None

    def _safe_c_ident(self, value: str) -> str:
        ident = re.sub(r"[^A-Za-z0-9_]", "_", value or "DRAGON")
        ident = re.sub(r"_+", "_", ident).strip("_")
        if not ident:
            ident = "DRAGON"
        if ident[0].isdigit():
            ident = "_" + ident
        return ident

    def _c_struct_from_fields(self, fields: list[str], struct_name: str) -> str:
        if not fields:
            return (
                "/* No IOCTL structure fields recovered yet.\n"
                "   Run Full Scan / Deep pseudocode scan, then select a function with SystemBuffer or Type3InputBuffer offset accesses. */"
            )
        parsed = []
        named = []
        for raw in fields:
            item = self._parse_struct_field(raw)
            if item.get("offset") is None:
                named.append(item)
            else:
                parsed.append(item)
        parsed.sort(key=lambda item: int(item.get("offset", 0)))
        lines = [
            "#include <stdint.h>",
            "",
            "#pragma pack(push, 1)",
            "typedef struct _%s {" % struct_name,
        ]
        cursor = 0
        for item in parsed:
            offset = int(item.get("offset", 0))
            size = self._field_decl_size(item)
            if offset > cursor:
                lines.append("    uint8_t reserved_%03X[0x%X];" % (cursor, offset - cursor))
                cursor = offset
            if len(item.get("variants", []) or []) > 1:
                lines.extend(self._c_union_for_field(item))
                cursor = max(cursor, offset + max(size, 1))
                continue
            ctype = self._c_type_for_field(item)
            name = self._field_c_name(item)
            comment = "offset=0x%X size=%s role=%s lines=%s source_ctype=%s" % (
                offset,
                item.get("size", "?"),
                item.get("role", "unknown"),
                item.get("lines", ""),
                item.get("ctype", "unknown"))
            if ctype == "uint8_t" and size not in {1, 2, 4, 8}:
                lines.append("    uint8_t %s[0x%X]; /* %s */" % (name, max(size, 1), comment))
                cursor = max(cursor, offset + max(size, 1))
            else:
                lines.append("    %s %s; /* %s */" % (ctype, name, comment))
                cursor = max(cursor, offset + max(size, self._sizeof_c_type(ctype)))
        for item in named:
            lines.append("    /* named field candidate: %s role=%s lines=%s */" % (
                item.get("name", "unknown"),
                item.get("role", "unknown"),
                item.get("lines", "")))
        lines += [
            "} %s;" % struct_name,
            "#pragma pack(pop)",
            "",
            "/* Review notes:",
            "   - Field names and types are inferred from decompiler offset accesses.",
            "   - Confirm signedness, pointer width, unions, and per-IOCTL layout manually.",
            "   - Use this as a harness/report starting point, not as final type truth. */"
        ]
        return "\n".join(lines)

    def _parse_struct_field(self, raw: str) -> dict[str, Any]:
        out: dict[str, Any] = {"raw": raw, "offset": None, "name": "field", "size": 8, "role": "unknown", "lines": "", "ctype": "unknown", "variants": []}
        m = re.search(r"\+0x([0-9A-Fa-f]+)\s+([A-Za-z_][A-Za-z0-9_]*)", raw)
        if m:
            out["offset"] = int(m.group(1), 16)
            out["name"] = m.group(2)
        else:
            m = re.search(r"named:([A-Za-z_][A-Za-z0-9_]*)", raw)
            if m:
                out["name"] = m.group(1)
        for key in ("size", "role", "lines", "ctype"):
            m = re.search(r"%s=([^\s]+)" % key, raw)
            if m:
                value = m.group(1)
                if key == "size":
                    try:
                        out[key] = int(value)
                    except Exception:
                        out[key] = value
                else:
                    out[key] = value
        m = re.search(r"variants=([^\s]+)", raw)
        if m:
            variants = []
            for raw_variant in m.group(1).split(";"):
                parts = raw_variant.split(":")
                if len(parts) < 3:
                    continue
                try:
                    variant_size = int(parts[1])
                except Exception:
                    variant_size = 8
                variants.append({
                    "ctype": parts[0] or "unknown",
                    "size": variant_size,
                    "role": parts[2] or "unknown",
                })
            out["variants"] = variants
        return out

    def _field_decl_size(self, item: dict[str, Any]) -> int:
        sizes = []
        try:
            sizes.append(int(item.get("size", 0) or 0))
        except Exception:
            pass
        for variant in item.get("variants", []) or []:
            try:
                sizes.append(int(variant.get("size", 0) or 0))
            except Exception:
                pass
        ctype = self._c_type_for_field(item)
        sizes.append(self._sizeof_c_type(ctype))
        return max([size for size in sizes if size > 0] or [1])

    def _c_union_for_field(self, item: dict[str, Any]) -> list[str]:
        offset = int(item.get("offset", 0) or 0)
        base_name = self._field_c_name(item)
        variants = item.get("variants", []) or []
        lines = ["    union { /* offset=0x%X union_candidate=yes lines=%s */" % (offset, item.get("lines", ""))]
        used: set[str] = set()
        for idx, variant in enumerate(variants[:8]):
            vitem = dict(item)
            vitem.update(variant)
            ctype = self._c_type_for_field(vitem)
            role = self._safe_c_ident(str(variant.get("role", "variant"))).lower()
            name = "%s_%s" % (base_name, role if role and role != "unknown" else "variant_%d" % idx)
            name = self._unique_c_name(name.lower(), used)
            size = int(variant.get("size", 0) or 0)
            comment = "variant source_ctype=%s size=%s role=%s" % (
                variant.get("ctype", "unknown"),
                size or "?",
                variant.get("role", "unknown"))
            if ctype == "uint8_t" and size not in {1, 2, 4, 8}:
                lines.append("        uint8_t %s[0x%X]; /* %s */" % (name, max(size, 1), comment))
            else:
                lines.append("        %s %s; /* %s */" % (ctype, name, comment))
        lines.append("    } %s_u;" % base_name)
        return lines

    def _unique_c_name(self, name: str, used: set[str]) -> str:
        base = self._safe_c_ident(name or "field").lower()
        candidate = base
        idx = 2
        while candidate in used:
            candidate = "%s_%d" % (base, idx)
            idx += 1
        used.add(candidate)
        return candidate

    def _field_c_name(self, item: dict[str, Any]) -> str:
        base = self._safe_c_ident(str(item.get("name", "field")))
        role = self._safe_c_ident(str(item.get("role", ""))).lower()
        if role and role != "unknown" and role not in base.lower():
            base = "%s_%s" % (base, role)
        return base.lower()

    def _c_type_for_field(self, item: dict[str, Any]) -> str:
        role = str(item.get("role", "")).lower()
        size = int(item.get("size", 0) or 0)
        if "physical" in role or "address" in role or "mdl" in role:
            return "uint64_t" if idainfo_is_64bit() or size == 8 else "uint32_t"
        if "size" in role or "length" in role or "pid" in role or "port" in role or "register" in role:
            if size in {1, 2, 4, 8}:
                return {1: "uint8_t", 2: "uint16_t", 4: "uint32_t", 8: "uint64_t"}[size]
            return "uint32_t"
        return {1: "uint8_t", 2: "uint16_t", 4: "uint32_t", 8: "uint64_t"}.get(size, "uint8_t")

    def _sizeof_c_type(self, ctype: str) -> int:
        return {"uint8_t": 1, "uint16_t": 2, "uint32_t": 4, "uint64_t": 8}.get(ctype, 1)

    def populate_fuzz_plan(self) -> None:
        self.fuzz_text.setPlainText(self.fuzz_plan_text())

    def _refresh_proof_ioctl_combo(self) -> None:
        if not hasattr(self, "proof_ioctl_combo"):
            return
        current = self._selected_proof_ioctl_value()
        candidates = self._ioctl_candidates()
        self.proof_ioctl_combo.blockSignals(True)
        self.proof_ioctl_combo.clear()
        if candidates:
            self.proof_ioctl_combo.addItem("Auto: top triage IOCTL", None)
            for item in candidates[:80]:
                label = "%s %s %s in %s (%s)" % (
                    item.get("hex", ""),
                    item.get("access", ""),
                    item.get("method", ""),
                    item.get("function", ""),
                    ea_text(item.get("function_ea", item.get("ea", idc.BADADDR))))
                self.proof_ioctl_combo.addItem(label, int(item.get("value", 0)))
            if current:
                for idx in range(self.proof_ioctl_combo.count()):
                    try:
                        if int(self.proof_ioctl_combo.itemData(idx) or 0) == int(current):
                            self.proof_ioctl_combo.setCurrentIndex(idx)
                            break
                    except Exception:
                        continue
        else:
            self.proof_ioctl_combo.addItem("No decoded IOCTL yet", None)
        self.proof_ioctl_combo.blockSignals(False)

    def _selected_proof_ioctl_value(self) -> int | None:
        if not hasattr(self, "proof_ioctl_combo"):
            return None
        try:
            data = self.proof_ioctl_combo.currentData()
            if data is None:
                return None
            value = int(data)
            return value if value > 0 else None
        except Exception:
            return None

    def _selected_or_top_ioctl(self) -> dict[str, Any] | None:
        candidates = self._ioctl_candidates()
        if not candidates:
            return None
        selected = self._selected_proof_ioctl_value()
        if selected is not None:
            for item in candidates:
                if int(item.get("value", 0)) == int(selected):
                    return item
        return candidates[0]

    def proof_pack_text_report(self) -> str:
        meta = self.analyzer.meta or {
            "file": input_filename(),
            "path": input_path(),
            "sha256": input_sha256()
        }
        device = self.device_path_edit.text().strip() or "<set device path, e.g. \\\\.\\Name>"
        service = self.service_name_edit.text().strip() or os.path.splitext(input_filename())[0]
        driver = self.driver_path_edit.text().strip() or meta.get("path", "")
        focus = self._selected_or_top_ioctl()
        dispatch_rows = self._dispatch_assignment_rows()
        maps = self._ioctl_static_maps()
        focus_map = self._ioctl_static_map(focus) if focus else None

        lines = [
            "Dragon Reverse MSRC/Intigriti Proof Pack",
            "",
            "Interpretation guardrails",
        ]
        lines.extend("  - " + item for item in TRIAGE_GUARDRAILS)

        lines += [
            "",
            "Target identity",
            "  File: %s" % meta.get("file", ""),
            "  Driver path: %s" % driver,
            "  SHA256: %s" % meta.get("sha256", ""),
            "  Version: collect with exported PowerShell probe or file properties.",
            "  Authenticode signer: collect with exported PowerShell probe.",
            "  Device path under test: %s" % device,
            "  Service name: %s" % service,
            "",
            "Ideal proof order",
        ]
        for idx, item in enumerate(BOUNTY_PROOF_ORDER, 1):
            lines.append("  %d. %s" % (idx, item))

        lines += [
            "",
            "Evidence status worksheet",
            "  [static-ready] SHA256: %s" % (meta.get("sha256", "") or "missing"),
            "  [dynamic-needed] File version/signature/file ACL: run exported PowerShell probe.",
            "  [dynamic-needed] Low-priv CreateFile matrix for %s: run the probe as a standard user first, then elevated for comparison." % device,
            "  [static-ready if listed below] Dispatch assignment IRP_MJ_DEVICE_CONTROL.",
            "  [static-ready if listed below] IOCTL access/method table.",
            "  [manual-needed] Per-IOCTL exact switch/case branch and structure fields before claiming exploitability.",
            "",
            "Controlled proof on %s" % device,
            "  1. Export the PowerShell probe from Dynamic Proof Lab and run it in a disposable VM under a low-privileged user.",
            "  2. Save transcript, OS build, token context, service state, signer, file ACL, and CreateFile matrix.",
            "  3. Repeat only the CreateFile matrix elevated to show low-priv vs admin difference.",
            "  4. Pick one IOCTL from the Focus IOCTL section and document static reachability to one sink before any active IOCTL test.",
            "  5. Export the C++ harness and run one explicit IOCTL proof case with JSONL logging after you identify a no-op/query or harmless negative-control input.",
            "  6. Attach the JSONL line, console output, probe transcript, and before/after state for any reversible proof.",
        ]

        lines += ["", "Focus IOCTL"]
        if focus:
            lines.extend(self._format_ioctl_focus(focus, focus_map))
            lines.extend(self._focus_ioctl_repro_commands(focus, device))
        else:
            lines.append("  - No decoded IOCTL yet. Run Full Scan / Deep pseudocode scan and inspect the dispatcher switch manually.")

        lines += ["", "Dispatcher evidence"]
        if dispatch_rows:
            for row in dispatch_rows[:20]:
                lines.append("  - %s %s assigns %s to IRP_MJ_DEVICE_CONTROL%s" % (
                    ea_text(row.get("owner_ea", idc.BADADDR)),
                    row.get("owner", ""),
                    row.get("target", ""),
                    (" (%s)" % ea_text(row.get("target_ea", idc.BADADDR))) if row.get("target_ea", idc.BADADDR) != idc.BADADDR else ""))
                if row.get("evidence"):
                    lines.append("    evidence: %s" % row.get("evidence"))
        else:
            lines.append("  - No explicit dispatch assignment recovered yet. Inspect DriverEntry/device setup pseudocode and MajorFunction[14].")

        lines += ["", "IOCTL access/method evidence"]
        candidates = self._ioctl_candidates()
        if candidates:
            for item in candidates[:40]:
                risk = []
                if item.get("access") == "FILE_ANY_ACCESS":
                    risk.append("FILE_ANY_ACCESS")
                if item.get("method") == "METHOD_NEITHER":
                    risk.append("METHOD_NEITHER")
                lines.append("  - %s at %s in %s: %s %s device=0x%X function=0x%X%s" % (
                    item.get("hex", ""),
                    ea_text(item.get("ea", idc.BADADDR)),
                    item.get("function", ""),
                    item.get("access", ""),
                    item.get("method", ""),
                    int(item.get("device_type", 0)),
                    int(item.get("function_code", item.get("function", 0))),
                    (" risk=" + ",".join(risk)) if risk else ""))
        else:
            lines.append("  - No IOCTL constants decoded yet.")

        lines += ["", "Per-IOCTL static input-to-sink map"]
        if maps:
            for item in maps[:20]:
                lines.extend(self._format_ioctl_static_map(item))
        else:
            lines.append("  - No map available. Run Full Scan so pseudocode facts and primitive chains are built.")

        lines += [
            "",
            "Suggested report wording",
            "  - Static result: 'Dragon Reverse identified a candidate IOCTL path. The chain is classified as triage evidence until dynamic reachability is shown.'",
            "  - Dynamic result: 'A low-privileged user can/cannot open %s with the following access matrix: ...'" % device,
            "  - IOCTL proof result: 'The selected IOCTL was invoked with an explicit zero-length or zero-filled buffer; the harness logged ok/error/bytes_returned in JSONL. No exploit payload was generated by the tool.'",
            "  - Impact claim: only make it after one precise IOCTL has a deterministic, reversible proof and direct-denial vs driver-mediated controls.",
            "",
            "Do not submit the score or pseudocode chain alone as proof. Submit hash/version/signature, low-priv device access, dispatcher assignment, IOCTL access/method, static field-to-sink trace, and controlled dynamic result together."
        ]
        return "\n".join(lines)

    def _format_ioctl_focus(self, focus: dict[str, Any], focus_map: dict[str, Any] | None) -> list[str]:
        lines = [
            "  - IOCTL: %s" % focus.get("hex", ""),
            "  - Function: %s at %s" % (focus.get("function", ""), ea_text(focus.get("function_ea", focus.get("ea", idc.BADADDR)))),
            "  - Access/method: %s / %s" % (focus.get("access", ""), focus.get("method", "")),
            "  - Device/function: 0x%X / 0x%X" % (int(focus.get("device_type", 0)), int(focus.get("function_code", focus.get("function", 0)))),
            "  - Proof goal: prove low-privileged reachability first, then statically document which input fields can reach one selected sink.",
        ]
        if focus_map and focus_map.get("links"):
            best = focus_map["links"][0]
            lines.append("  - Best current static target: %s %s via %s" % (
                best.get("target_ea_text", ""),
                best.get("target", ""),
                best.get("link_level", "")))
            if best.get("sinks"):
                lines.append("  - Sink candidates: %s" % ", ".join(best.get("sinks", [])[:8]))
            if best.get("dataflow_lite"):
                lines.append("  - Ctree-lite dataflow: %s" % " | ".join(best.get("dataflow_lite", [])[:3]))
            if best.get("struct_fields"):
                lines.append("  - IOCTL struct fields: %s" % " | ".join(best.get("struct_fields", [])[:4]))
            if best.get("probe_size_mismatch"):
                lines.append("  - Probe size mismatch hypothesis: %s" % " | ".join(best.get("probe_size_mismatch", [])[:3]))
            elif best.get("probe_size_checks"):
                lines.append("  - Probe size checks: %s" % " | ".join(best.get("probe_size_checks", [])[:3]))
        return lines

    def _focus_ioctl_repro_commands(self, focus: dict[str, Any], device: str) -> list[str]:
        ioctl_hex = focus.get("hex", "0xXXXXXXXX")
        safe_device = device if device and not device.startswith("<") else r"\\.\Name"
        case_id = "%s_%s" % (input_filename() or "driver", ioctl_hex.replace("0x", "ioctl_"))
        return [
            "  - Harness build: cl /EHsc /std:c++17 dragon_reverse_harness.cpp",
            "  - Open-only run: dragon_reverse_harness.exe --device %s --jsonl proof_%s.jsonl --case-id %s_open_only" % (safe_device, case_id, case_id),
            "  - Zero-length IOCTL proof: dragon_reverse_harness.exe --device %s --jsonl proof_%s.jsonl --case-id %s_zero_len --allow-deviceiocontrol --i-understand-this-can-crash --ioctl %s --out-size 0" % (safe_device, case_id, case_id, ioctl_hex),
            "  - Zero-filled boundary proof: dragon_reverse_harness.exe --device %s --jsonl proof_%s.jsonl --case-id %s_in16_out64 --allow-deviceiocontrol --i-understand-this-can-crash --ioctl %s --in-size 16 --out-size 64" % (safe_device, case_id, case_id, ioctl_hex),
        ]

    def _format_ioctl_static_map(self, item: dict[str, Any]) -> list[str]:
        ioctl = item.get("ioctl", {})
        lines = [
            "  - %s in %s at %s: %s %s" % (
                ioctl.get("hex", ""),
                ioctl.get("function", ""),
                ea_text(ioctl.get("function_ea", ioctl.get("ea", idc.BADADDR))),
                ioctl.get("access", ""),
                ioctl.get("method", ""))
        ]
        input_facts = item.get("input_facts", [])
        if input_facts:
            lines.append("    input facts: %s" % " | ".join(input_facts[:5]))
        links = item.get("links", [])
        if links:
            for link in links[:8]:
                lines.append("    -> %s %s [%s]" % (
                    link.get("target_ea_text", ""),
                    link.get("target", ""),
                    link.get("link_level", "")))
                if link.get("sinks"):
                    lines.append("       sinks: %s" % ", ".join(link.get("sinks", [])[:8]))
                if link.get("dataflow_lite"):
                    lines.append("       ctree-lite: %s" % " | ".join(link.get("dataflow_lite", [])[:3]))
                if link.get("struct_fields"):
                    lines.append("       struct: %s" % " | ".join(link.get("struct_fields", [])[:4]))
                if link.get("probe_size_mismatch"):
                    lines.append("       probe-size-review: %s" % " | ".join(link.get("probe_size_mismatch", [])[:3]))
                elif link.get("probe_size_checks"):
                    lines.append("       probe-size-checks: %s" % " | ".join(link.get("probe_size_checks", [])[:3]))
                if link.get("path_validation"):
                    lines.append("       validation-window: %s" % " | ".join(link.get("path_validation", [])[:3]))
        else:
            lines.append("    -> no sink link yet; inspect switch/case and callee arguments manually.")
        return lines

    def _dispatch_assignment_rows(self) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        by_name = {fn.name: fn for fn in self.analyzer.functions}
        for owner in self.analyzer.functions:
            for target_name in owner.pseudocode_facts.get("dispatch_assignments", []) or []:
                target = by_name.get(target_name)
                rows.append({
                    "owner": owner.name,
                    "owner_ea": owner.ea,
                    "target": target_name,
                    "target_ea": target.ea if target else idc.BADADDR,
                    "evidence": "Hex-Rays pseudocode dispatch_assignments"
                })
        if not rows:
            for target in self.analyzer.functions:
                for evidence in target.evidence:
                    if evidence.startswith("dispatch-assignment-from-pseudocode:"):
                        owner_name = evidence.split(":", 1)[1]
                        owner = by_name.get(owner_name)
                        rows.append({
                            "owner": owner_name,
                            "owner_ea": owner.ea if owner else idc.BADADDR,
                            "target": target.name,
                            "target_ea": target.ea,
                            "evidence": evidence
                        })
        seen: set[tuple[str, str]] = set()
        unique = []
        for row in rows:
            key = (str(row.get("owner", "")), str(row.get("target", "")))
            if key in seen:
                continue
            seen.add(key)
            unique.append(row)
        return unique

    def _ioctl_static_maps(self) -> list[dict[str, Any]]:
        out = []
        for item in self._ioctl_candidates()[:40]:
            out.append(self._ioctl_static_map(item))
        return out

    def _ioctl_static_map(self, item: dict[str, Any] | None) -> dict[str, Any]:
        if not item:
            return {}
        entry = self._function_by_ea(int(item.get("function_ea", item.get("ea", idc.BADADDR))))
        input_facts = self._input_facts_for_function(entry) if entry else []
        links = []
        if entry:
            chains = [
                chain for chain in self.analyzer.primitive_chains
                if chain.entry_ea == entry.ea or chain.entry == entry.name
            ]
            for chain in chains[:16]:
                target = self._function_by_ea(chain.target_ea)
                if not target:
                    continue
                links.append({
                    "target": target.name,
                    "target_ea": target.ea,
                    "target_ea_text": ea_text(target.ea),
                    "primitive": chain.primitive,
                    "chain_type": chain.chain_type,
                    "confidence": chain.confidence,
                    "link_level": self._static_link_level(chain, target),
                    "sinks": self._sink_summary_for_function(target),
                    "dataflow_lite": (target.pseudocode_facts.get("ctree_lite_dataflow") or [])[:8],
                    "struct_fields": (target.pseudocode_facts.get("ioctl_struct_fields") or [])[:12],
                    "probe_size_checks": (target.pseudocode_facts.get("probe_size_checks") or [])[:8],
                    "probe_size_mismatch": (target.pseudocode_facts.get("probe_size_mismatch") or [])[:8],
                    "path_validation": (target.pseudocode_facts.get("path_validation") or [])[:8],
                    "proof_focus": chain.proof_focus,
                    "confidence_reason": chain.confidence_reason
                })
            if not links:
                own_sinks = self._sink_summary_for_function(entry)
                if own_sinks:
                    links.append({
                        "target": entry.name,
                        "target_ea": entry.ea,
                        "target_ea_text": ea_text(entry.ea),
                        "primitive": ", ".join(sorted(entry.roles & SENSITIVE_REACHABILITY_ROLES)) or "same-function sensitive sink",
                        "chain_type": "pseudocode" if entry.pseudocode_facts else "strict",
                        "confidence": entry.score,
                        "link_level": "same-function sink; confirm switch/case branch manually",
                        "sinks": own_sinks,
                        "dataflow_lite": (entry.pseudocode_facts.get("ctree_lite_dataflow") or [])[:8],
                        "struct_fields": (entry.pseudocode_facts.get("ioctl_struct_fields") or [])[:12],
                        "probe_size_checks": (entry.pseudocode_facts.get("probe_size_checks") or [])[:8],
                        "probe_size_mismatch": (entry.pseudocode_facts.get("probe_size_mismatch") or [])[:8],
                        "path_validation": (entry.pseudocode_facts.get("path_validation") or [])[:8],
                        "proof_focus": "Prove input fields reach the same-function sink and are not rejected by guards.",
                        "confidence_reason": entry.confidence_reason
                    })
        return {
            "ioctl": dict(item),
            "entry": {
                "name": entry.name if entry else item.get("function", ""),
                "ea": entry.ea if entry else item.get("function_ea", item.get("ea", idc.BADADDR)),
                "ea_text": ea_text(entry.ea if entry else item.get("function_ea", item.get("ea", idc.BADADDR)))
            },
            "input_facts": input_facts,
            "links": links
        }

    def _function_by_ea(self, ea: int) -> FunctionSummary | None:
        if ea is None or ea == idc.BADADDR or ea < 0:
            return None
        func = ida_funcs.get_func(ea)
        start = int(func.start_ea) if func else int(ea)
        for fn in self.analyzer.functions:
            if fn.ea == start or fn.ea == ea:
                return fn
        return None

    def _input_facts_for_function(self, fn: FunctionSummary | None) -> list[str]:
        if not fn:
            return []
        facts = fn.pseudocode_facts or {}
        out = []
        for key in ("ioctl_surface", "user_buffers", "length_fields", "ctree_lite_dataflow", "ioctl_struct_fields", "probe_size_mismatch", "probe_size_checks", "guards"):
            values = facts.get(key) or []
            if values:
                out.append("%s=%s" % (key, ",".join(values[:5])))
        if fn.ioctls:
            out.append("decoded_ioctls=%s" % ",".join("%s/%s/%s/%s" % (i.get("hex", ""), i.get("access", ""), i.get("method", ""), i.get("source", "strict")) for i in fn.ioctls[:6]))
        return out

    def _sink_summary_for_function(self, fn: FunctionSummary | None) -> list[str]:
        if not fn:
            return []
        sinks: set[str] = set()
        facts = fn.pseudocode_facts or {}
        for key in ("memory_sinks", "port_sinks"):
            for value in facts.get(key, []) or []:
                if value in PROOF_SINK_TOKENS:
                    sinks.add(value)
        for call in fn.calls:
            for token in PROOF_SINK_TOKENS:
                if token.lower() in str(call).lower():
                    sinks.add(token)
        for mnemonic in fn.mnemonics:
            if mnemonic in {"in", "out", "ins", "outs"}:
                sinks.add(mnemonic)
        return sorted(sinks)

    def _static_link_level(self, chain: PrimitiveChain, target: FunctionSummary | None) -> str:
        parts = [chain.chain_type]
        if target and target.pseudocode_facts.get("ctree_lite_dataflow"):
            parts.append("ctree-lite dataflow edge")
        if target and target.pseudocode_facts.get("ioctl_struct_fields"):
            parts.append("IOCTL struct field recovery")
        if target and target.pseudocode_facts.get("path_validation"):
            parts.append("path-sensitive-lite validation window")
        if chain.chain_type != "strict":
            parts.append("not final proof")
        return "; ".join(parts)

    def export_proof_pack(self) -> None:
        path = ida_kernwin.ask_file(True, "*.txt", "Export Dragon Reverse MSRC/Intigriti proof pack (.txt or .json)")
        if not path:
            return
        if not self._ensure_analysis_for_export():
            return
        self.populate_dynamic_plan()
        self.populate_proof_pack()
        ext = os.path.splitext(path)[1].lower()
        with open(path, "w", encoding="utf-8", newline="\n") as f:
            if ext == ".json":
                json.dump(self._proof_pack_manifest(), f, indent=2)
            else:
                f.write(self.proof_pack_text_report())
                f.write("\n")
        self.status.setText("Exported proof pack: %s" % path)

    def export_visual_studio_project(self) -> None:
        path = ida_kernwin.ask_file(True, "*.sln", "Export Dragon Reverse Visual Studio proof project (.sln)")
        if not path:
            return
        if not self._ensure_analysis_for_export():
            return
        self.populate_dynamic_plan()
        self.populate_proof_pack()
        project_dir = os.path.dirname(os.path.abspath(path)) or os.getcwd()
        project_name = self._safe_c_ident(os.path.splitext(os.path.basename(path))[0] or "DragonReverseProof")
        if not project_name:
            project_name = "DragonReverseProof"
        os.makedirs(project_dir, exist_ok=True)
        sln_path = os.path.join(project_dir, "%s.sln" % project_name)
        vcxproj_path = os.path.join(project_dir, "%s.vcxproj" % project_name)
        filters_path = os.path.join(project_dir, "%s.vcxproj.filters" % project_name)
        harness_path = os.path.join(project_dir, "dragon_reverse_harness.cpp")
        header_path = os.path.join(project_dir, "dragon_reverse_structs.h")
        manifest_path = os.path.join(project_dir, "proof_manifest.json")
        proof_text_path = os.path.join(project_dir, "proof_pack.txt")
        readme_path = os.path.join(project_dir, "README_PROOF.txt")

        harness = self._cpp_harness_template()
        if '#include "dragon_reverse_structs.h"' not in harness:
            harness = harness.replace("#include <stdint.h>\n", "#include <stdint.h>\n#include \"dragon_reverse_structs.h\"\n", 1)

        files = {
            sln_path: self._vs_solution_template(project_name),
            vcxproj_path: self._vs_vcxproj_template(project_name),
            filters_path: self._vs_filters_template(),
            harness_path: harness,
            header_path: self._vs_struct_header(),
            proof_text_path: self.proof_pack_text_report() + "\n",
            readme_path: self._vs_readme(project_name),
        }
        for file_path, content in files.items():
            with open(file_path, "w", encoding="utf-8", newline="\n") as f:
                f.write(content)
        with open(manifest_path, "w", encoding="utf-8", newline="\n") as f:
            json.dump(self._proof_pack_manifest(), f, indent=2)
        self.status.setText("Exported Visual Studio proof project: %s" % project_dir)

    def _vs_solution_template(self, project_name: str) -> str:
        guid = "{B41F6C2D-7237-4D5B-922D-70C2A88A8844}"
        vc_guid = "{8BC9CEB8-8B4A-11D0-8D11-00A0C91BC942}"
        return """Microsoft Visual Studio Solution File, Format Version 12.00
# Visual Studio Version 17
VisualStudioVersion = 17.0.31903.59
MinimumVisualStudioVersion = 10.0.40219.1
Project("%s") = "%s", "%s.vcxproj", "%s"
EndProject
Global
	GlobalSection(SolutionConfigurationPlatforms) = preSolution
		Debug|x64 = Debug|x64
		Release|x64 = Release|x64
	EndGlobalSection
	GlobalSection(ProjectConfigurationPlatforms) = postSolution
		%s.Debug|x64.ActiveCfg = Debug|x64
		%s.Debug|x64.Build.0 = Debug|x64
		%s.Release|x64.ActiveCfg = Release|x64
		%s.Release|x64.Build.0 = Release|x64
	EndGlobalSection
	GlobalSection(SolutionProperties) = preSolution
		HideSolutionNode = FALSE
	EndGlobalSection
EndGlobal
""" % (vc_guid, project_name, project_name, guid, guid, guid, guid, guid)

    def _vs_vcxproj_template(self, project_name: str) -> str:
        guid = "{B41F6C2D-7237-4D5B-922D-70C2A88A8844}"
        return """<?xml version="1.0" encoding="utf-8"?>
<Project DefaultTargets="Build" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <ItemGroup Label="ProjectConfigurations">
    <ProjectConfiguration Include="Debug|x64">
      <Configuration>Debug</Configuration>
      <Platform>x64</Platform>
    </ProjectConfiguration>
    <ProjectConfiguration Include="Release|x64">
      <Configuration>Release</Configuration>
      <Platform>x64</Platform>
    </ProjectConfiguration>
  </ItemGroup>
  <PropertyGroup Label="Globals">
    <VCProjectVersion>17.0</VCProjectVersion>
    <Keyword>Win32Proj</Keyword>
    <ProjectGuid>%s</ProjectGuid>
    <RootNamespace>%s</RootNamespace>
    <WindowsTargetPlatformVersion>10.0</WindowsTargetPlatformVersion>
  </PropertyGroup>
  <Import Project="$(VCTargetsPath)\\Microsoft.Cpp.Default.props" />
  <PropertyGroup Condition="'$(Configuration)|$(Platform)'=='Debug|x64'" Label="Configuration">
    <ConfigurationType>Application</ConfigurationType>
    <UseDebugLibraries>true</UseDebugLibraries>
    <PlatformToolset>v143</PlatformToolset>
    <CharacterSet>Unicode</CharacterSet>
  </PropertyGroup>
  <PropertyGroup Condition="'$(Configuration)|$(Platform)'=='Release|x64'" Label="Configuration">
    <ConfigurationType>Application</ConfigurationType>
    <UseDebugLibraries>false</UseDebugLibraries>
    <PlatformToolset>v143</PlatformToolset>
    <WholeProgramOptimization>true</WholeProgramOptimization>
    <CharacterSet>Unicode</CharacterSet>
  </PropertyGroup>
  <Import Project="$(VCTargetsPath)\\Microsoft.Cpp.props" />
  <ItemDefinitionGroup Condition="'$(Configuration)|$(Platform)'=='Debug|x64'">
    <ClCompile>
      <WarningLevel>Level3</WarningLevel>
      <SDLCheck>true</SDLCheck>
      <LanguageStandard>stdcpp17</LanguageStandard>
      <ConformanceMode>true</ConformanceMode>
    </ClCompile>
    <Link>
      <SubSystem>Console</SubSystem>
    </Link>
  </ItemDefinitionGroup>
  <ItemDefinitionGroup Condition="'$(Configuration)|$(Platform)'=='Release|x64'">
    <ClCompile>
      <WarningLevel>Level3</WarningLevel>
      <FunctionLevelLinking>true</FunctionLevelLinking>
      <IntrinsicFunctions>true</IntrinsicFunctions>
      <SDLCheck>true</SDLCheck>
      <LanguageStandard>stdcpp17</LanguageStandard>
      <ConformanceMode>true</ConformanceMode>
    </ClCompile>
    <Link>
      <SubSystem>Console</SubSystem>
      <EnableCOMDATFolding>true</EnableCOMDATFolding>
      <OptimizeReferences>true</OptimizeReferences>
    </Link>
  </ItemDefinitionGroup>
  <ItemGroup>
    <ClCompile Include="dragon_reverse_harness.cpp" />
  </ItemGroup>
  <ItemGroup>
    <ClInclude Include="dragon_reverse_structs.h" />
  </ItemGroup>
  <Import Project="$(VCTargetsPath)\\Microsoft.Cpp.targets" />
</Project>
""" % (guid, project_name)

    def _vs_filters_template(self) -> str:
        return """<?xml version="1.0" encoding="utf-8"?>
<Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <ItemGroup>
    <ClCompile Include="dragon_reverse_harness.cpp" />
  </ItemGroup>
  <ItemGroup>
    <ClInclude Include="dragon_reverse_structs.h" />
  </ItemGroup>
</Project>
"""

    def _vs_struct_header(self) -> str:
        structs = self._generated_c_structs_for_report()
        lines = [
            "#pragma once",
            "#include <stdint.h>",
            "",
            "/* Generated by Dragon Reverse.",
            "   Types, unions, and field names are inferred from Hex-Rays pseudocode.",
            "   Confirm every layout against the selected IOCTL switch/case before use. */",
            "",
        ]
        if not structs:
            lines += [
                "#pragma pack(push, 1)",
                "typedef struct _DRAGON_IOCTL_REQUEST {",
                "    uint8_t reserved[1]; /* No structure fields recovered yet. */",
                "} DRAGON_IOCTL_REQUEST;",
                "#pragma pack(pop)",
                "",
            ]
            return "\n".join(lines)
        for item in structs[:40]:
            struct_text = item.get("c_struct", "")
            struct_text = struct_text.replace("#include <stdint.h>\n\n", "")
            lines.append("/* Function %s %s */" % (item.get("ea_text", ""), item.get("function", "")))
            lines.append(struct_text.strip())
            lines.append("")
        return "\n".join(lines)

    def _vs_readme(self, project_name: str) -> str:
        focus = self._selected_or_top_ioctl()
        device = self.device_path_edit.text().strip() or r"\\.\Name"
        ioctl = focus.get("hex", "0xXXXXXXXX") if focus else "0xXXXXXXXX"
        return "\n".join([
            "Dragon Reverse Visual Studio Proof Project",
            "",
            "Files",
            "  - %s.sln / %s.vcxproj: Visual Studio 2022 x64 project." % (project_name, project_name),
            "  - dragon_reverse_harness.cpp: controlled CreateFile/DeviceIoControl harness.",
            "  - dragon_reverse_structs.h: inferred IOCTL request structs; union fields mark conflicting offset variants.",
            "  - proof_manifest.json: structured MSRC/Intigriti proof pack.",
            "  - proof_pack.txt: report-ready static/dynamic evidence worksheet.",
            "",
            "Build",
            "  msbuild %s.sln /p:Configuration=Release /p:Platform=x64" % project_name,
            "",
            "Suggested first runs",
            "  x64\\Release\\%s.exe --device %s --jsonl proof_open_only.jsonl --case-id open_only" % (project_name, device),
            "  x64\\Release\\%s.exe --device %s --jsonl proof_%s.jsonl --case-id zero_len --allow-deviceiocontrol --i-understand-this-can-crash --ioctl %s --out-size 0" % (project_name, device, ioctl.replace("0x", "ioctl_"), ioctl),
            "",
            "Report discipline",
            "  - A pseudocode chain is triage evidence until dynamic reachability is shown.",
            "  - A ProbeForRead/ProbeForWrite mismatch is a review hypothesis until the exact path and structure layout are confirmed.",
            "  - Keep one IOCTL, one case ID, one JSONL line, and one reversible proof goal per submitted claim.",
            ""
        ])

    def _proof_pack_manifest(self) -> dict[str, Any]:
        meta = self.analyzer.meta or {
            "file": input_filename(),
            "path": input_path(),
            "sha256": input_sha256()
        }
        focus = self._selected_or_top_ioctl()
        focus_struct = ""
        focus_map = self._ioctl_static_map(focus) if focus else {}
        for link in focus_map.get("links", []) if focus_map else []:
            fields = link.get("struct_fields", []) or []
            if fields:
                focus_struct = self._c_struct_from_fields(fields, "%s_IOCTL_REQUEST" % self._safe_c_ident(str(link.get("target", "DRAGON"))).upper())
                break
        return {
            "report_type": "Dragon Reverse MSRC/Intigriti proof pack",
            "generated_utc": datetime.now(timezone.utc).isoformat(),
            "interpretation_guardrails": TRIAGE_GUARDRAILS,
            "ideal_proof_order": BOUNTY_PROOF_ORDER,
            "target": {
                "file": meta.get("file", ""),
                "path": self.driver_path_edit.text().strip() or meta.get("path", ""),
                "sha256": meta.get("sha256", ""),
                "device_path": self.device_path_edit.text().strip(),
                "service_name": self.service_name_edit.text().strip(),
                "known_profile": meta.get("known_profile", {}),
                "known_profile_source": meta.get("known_profile_source", "")
            },
            "focus_ioctl": focus,
            "dispatch_assignments": self._dispatch_assignment_rows(),
            "ioctl_candidates": self._ioctl_candidates()[:80],
            "ioctl_static_maps": self._ioctl_static_maps(),
            "focus_c_struct": focus_struct,
            "createfile_probe_required": True,
            "active_deviceiocontrol_executed_by_plugin": False,
            "proof_pack_text": self.proof_pack_text_report()
        }

    def fuzz_plan_text(self) -> str:
        candidates = self._ioctl_candidates()
        chains = self.analyzer.primitive_chains[:20]
        lines = [
            "Dragon Reverse Controlled Fuzz Plan",
            "",
            "Safety model",
            "  - IDA does not execute fuzzing or DeviceIoControl.",
            "  - Use a disposable VM with snapshot, kernel debugger, and crash dump collection.",
            "  - Start with CreateFile-only evidence and zero-length/no-op IOCTL probes.",
            "  - Never target protected/security processes first; process-kill tests use an owned harmless process only.",
            "  - Stop on first crash, hang, verifier bugcheck, or state mutation.",
            "",
            "Suggested IOCTL campaign"
        ]
        if candidates:
            for item in candidates[:30]:
                risk = "high" if item.get("access") == "FILE_ANY_ACCESS" or item.get("method") == "METHOD_NEITHER" else "medium"
                lines.append("  - %s %s %s risk=%s function=%s ea=%s" % (
                    item.get("hex", ""),
                    item.get("access", ""),
                    item.get("method", ""),
                    risk,
                    item.get("function", ""),
                    ea_text(item.get("ea", idc.BADADDR))))
                lines.append("    stages: open-only -> zero-length -> expected-size-zeroed -> boundary sizes [1,4,8,16,32,64,128,256,512,1024]")
        else:
            lines.append("  - No decoded IOCTLs. Use Deep pseudocode scan to recover dispatcher and switch/case constants first.")

        lines += ["", "Chain-driven fuzz focus"]
        if chains:
            for chain in chains:
                lines.append("  - [%s/%d/%s] %s -> %s | %s" % (
                    chain.chain_type, chain.confidence, chain.review_status, chain.entry, chain.target, chain.primitive))
                lines.append("    guardrails: %s" % self._fuzz_guardrails_for_chain(chain))
        else:
            lines.append("  - No chains yet. Do not fuzz blind; recover IOCTL dispatcher and expected structures first.")

        lines += [
            "",
            "Recommended instrumentation",
            "  - Driver Verifier for the target driver only.",
            "  - WinDbg attached with crash dumps enabled.",
            "  - ETW/ProcMon only for non-invasive evidence collection.",
            "  - Transcript every command line, return code, GetLastError, bytes returned, and before/after state.",
            "",
            "Report rule",
            "  - Fuzz results are supporting evidence. A bounty claim still needs a minimal deterministic PoC or a reversible proof sequence."
        ]
        return "\n".join(lines)

    def _fuzz_guardrails_for_chain(self, chain: PrimitiveChain) -> str:
        primitive = chain.primitive.lower()
        if "process" in primitive or "token" in primitive:
            return "owned sacrificial process only; collect direct-denial vs driver-mediated result"
        if "physical" in primitive or "mdl" in primitive or "memory" in primitive:
            return "no arbitrary kernel addresses; start with invalid/null ranges and query-only paths"
        if "port" in primitive or "firmware" in primitive or "pci" in primitive:
            return "no write operations until register ownership and reversible target are identified"
        if "registry" in primitive:
            return "read-only before/after first; no writes without reversible test key"
        return "zero-length and query-style inputs before any state-changing test"

    def export_fuzz_manifest(self) -> None:
        path = ida_kernwin.ask_file(True, "*.json", "Export Dragon Reverse controlled fuzz manifest")
        if not path:
            return
        with open(path, "w", encoding="utf-8", newline="\n") as f:
            json.dump(self._fuzz_manifest(), f, indent=2)
        self.status.setText("Exported controlled fuzz manifest: %s" % path)

    def _fuzz_manifest(self) -> dict[str, Any]:
        return {
            "mode": "controlled-fuzz-plan",
            "auto_execute": False,
            "target": self.analyzer.meta or {},
            "device_path": self.device_path_edit.text().strip(),
            "ioctl_candidates": self._ioctl_candidates()[:80],
            "primitive_chains": [chain.__dict__ for chain in self.analyzer.primitive_chains[:80]],
            "size_schedule": [0, 1, 4, 8, 16, 32, 64, 128, 256, 512, 1024],
            "stages": ["open-only", "zero-length", "expected-size-zeroed", "boundary-size-zeroed", "manual-case-specific"],
            "stop_conditions": ["crash", "hang", "bugcheck", "state mutation", "unexpected privileged effect"],
            "safety": [
                "Use disposable VM snapshot",
                "Do not fuzz blind without a recovered dispatcher",
                "Do not generate payloads automatically",
                "Use owned harmless processes for process-control checks",
                "Record direct-denial and driver-mediated controls"
            ],
            "plan_text": self.fuzz_plan_text()
        }

    def dynamic_plan_text(self) -> str:
        meta = self.analyzer.meta or {
            "file": input_filename(),
            "path": input_path(),
            "sha256": input_sha256()
        }
        device = self.device_path_edit.text().strip() or "<set device path, e.g. \\\\.\\Name>"
        service = self.service_name_edit.text().strip() or "<set service name>"
        driver = self.driver_path_edit.text().strip() or meta.get("path", "")
        guesses = self._device_path_guesses()
        ioctl_candidates = self._ioctl_candidates()
        top_families = self.analyzer.correlations[:10]

        lines = [
            "Dragon Reverse Dynamic Proof Lab",
            "",
            "Target",
            "  File: %s" % meta.get("file", ""),
            "  Driver path: %s" % driver,
            "  SHA256: %s" % meta.get("sha256", ""),
            "  Device path: %s" % device,
            "  Service name: %s" % service,
            "",
            "Non-destructive proof sequence",
            "  1. Record OS build, kernel version, VM/snapshot ID, and test account type.",
            "  2. Record token context: user SID, groups, privileges, elevation, integrity level.",
            "  3. Record driver file hash, Authenticode signer, file ACL, and service state.",
            "  4. Check service-key access without writing: HKLM\\SYSTEM\\CurrentControlSet\\Services\\%s." % service,
            "  5. Run CreateFile access matrix against %s: 0, GENERIC_READ, GENERIC_WRITE, GENERIC_READ|GENERIC_WRITE, WRITE_DAC." % device,
            "  6. Compare low-privileged vs elevated results; the low-privileged result is the important one for EoP/ACL findings.",
            "  7. For weak-device findings, a bounty-grade negative/positive control is: protected resource action denied directly, but device open/reachability succeeds as non-admin.",
            "  8. For registry-write findings, read before/after values only; do not mutate values until you have a case-specific safe command.",
            "  9. For MSR, physical-memory, MDL, token, firmware, namespace, ALPC/WMI, or process-object findings, first prove reachability and authorization failure/success. Active IOCTL confirmation must be case-specific and reversible.",
            "",
            "Dynamic safety gates",
            "  - The PowerShell probe exported by this plugin does not call DeviceIoControl.",
            "  - The C++ harness keeps DeviceIoControl disabled unless both --allow-deviceiocontrol and --i-understand-this-can-crash are provided.",
            "  - The harness does not generate exploit payloads. It only sends user-provided bytes, zero-length buffers, or explicit zero-filled sizes to selected IOCTLs.",
            "  - Use --jsonl, --case-id, --in-size, --out-size, --repeat, and --sleep-ms to produce reproducible proof artifacts.",
            "  - Export the evidence manifest to keep target metadata, candidates, controls, and proof artifacts together.",
            "  - A confidence score of 100 is a triage priority, not a confirmed vulnerability.",
            "  - chain_type=pseudocode requires exact branch/data-flow confirmation before it becomes report proof.",
            "",
            "Device path guesses from strings"
        ]
        if guesses:
            lines.extend("  - %s" % g for g in guesses[:20])
        else:
            lines.append("  - No device-path strings found yet. Run static analysis or inspect IoCreateDevice/IoCreateSymbolicLink xrefs.")

        lines += ["", "Top IOCTL candidates"]
        if ioctl_candidates:
            for item in ioctl_candidates[:30]:
                lines.append("  - %s at %s in %s: %s %s confidence=%s device=0x%X function=0x%X" % (
                    item["hex"],
                    ea_text(item["ea"]),
                    item["function"],
                    item["access"],
                    item["method"],
                    item.get("confidence", "unknown"),
                    int(item.get("device_type", 0)),
                    int(item.get("function_code", 0))))
                if item.get("source"):
                    lines.append("    source: %s" % item.get("source"))
        else:
            lines.append("  - No suspicious constants decoded yet.")

        profile = (self.analyzer.meta or {}).get("known_profile") or {}
        if profile:
            lines += ["", "Known BYOVD profile guidance"]
            lines.append("  - Profile: %s (%s)" % (profile.get("name", ""), (self.analyzer.meta or {}).get("known_profile_source", "")))
            primitives = profile.get("primitives", []) or []
            if primitives:
                lines.append("  - Expected primitive classes: %s" % ", ".join(primitives))
            if profile.get("cves"):
                lines.append("  - CVE references: %s" % ", ".join(profile.get("cves", [])))
            if profile.get("projects"):
                lines.append("  - Public tooling references: %s" % ", ".join(profile.get("projects", [])))
            if (self.analyzer.meta or {}).get("known_profile_source") == "filename_seed":
                lines.append("  - Filename-only match: collect exact hash, signer, version and LOLDrivers/API evidence before treating it as a known vulnerable sample.")

        lines += ["", "Top primitive chains"]
        if self.analyzer.primitive_chains:
            for chain in self.analyzer.primitive_chains[:20]:
                lines.append("  - [%s/%d/%s/%s] %s -> %s | %s | %s | proof: %s" % (
                    chain.severity,
                    chain.confidence,
                    chain.chain_type,
                    chain.review_status,
                    chain.entry,
                    chain.target,
                    chain.primitive,
                    chain.access_surface,
                    chain.proof_focus))
        else:
            lines.append("  - No strict primitive chain yet. Run Full Scan or inspect dispatcher assignments manually.")

        lines += ["", "Top deep pseudocode hypotheses"]
        deep_rows = [
            fn for fn in self.analyzer.functions
            if fn.pseudocode_facts and (self.analyzer._facts_have_sensitive_signal(fn.pseudocode_facts) or fn.pseudocode_facts.get("dispatch_assignments"))
        ]
        deep_rows.sort(key=lambda fn: (self.analyzer._pseudocode_risk_score(fn, fn.pseudocode_facts), fn.score), reverse=True)
        if deep_rows:
            for fn in deep_rows[:12]:
                lines.append("  - %s %s pseudo_risk=%d facts=%s" % (
                    ea_text(fn.ea),
                    fn.name,
                    self.analyzer._pseudocode_risk_score(fn, fn.pseudocode_facts),
                    self.analyzer._pseudocode_fact_signal(fn.pseudocode_facts)))
        else:
            lines.append("  - No structured pseudocode hypotheses yet. Use the Deep pseudocode scan button.")

        lines += ["", "Function role map"]
        role_rows = [fn for fn in self.analyzer.functions if fn.roles]
        if role_rows:
            for fn in role_rows[:30]:
                lines.append("  - %s %s score=%d roles=%s families=%s" % (
                    ea_text(fn.ea),
                    fn.name,
                    fn.score,
                    ", ".join(sorted(fn.roles)),
                    ", ".join(sorted(fn.families))))
        else:
            lines.append("  - Run static analysis, then Run + pseudocode for richer role inference.")

        lines += ["", "Correlation-driven proof focus"]
        if top_families:
            for row in top_families:
                lines.append("  - %s [%s/%s]: %s" % (
                    row.get("name", ""),
                    row.get("severity", ""),
                    row.get("confidence", ""),
                    row.get("review", "")))
        else:
            lines.append("  - Run static analysis first.")

        lines += [
            "",
            "Bounty evidence checklist",
            "  - Exact driver version, SHA256, signer, OS build, test account type, integrity level.",
            "  - Service state, ImagePath, service SDDL, driver file ACL, and device open matrix.",
            "  - IRP_MJ_DEVICE_CONTROL assignment and IOCTL FILE_ANY_ACCESS/METHOD_NEITHER evidence.",
            "  - Per-IOCTL static trace from input fields to MmMapIoSpace, MmMapLockedPagesSpecifyCache, IoAllocateMdl, or port I/O.",
            "  - Direct-denial control: show the same user cannot perform the privileged operation directly.",
            "  - Driver-mediated positive: show the driver exposes enough access to reach the privileged path.",
            "  - Before/after state for reversible tests only.",
            "  - Crash-free logs, command lines, return codes, exported manifest, and WinDbg/ETW notes if used.",
            "",
            "Do not submit static-only claims as confirmed. Label static-only chains as candidates until dynamic evidence exists."
        ]
        return "\n".join(lines)

    def export_powershell_probe(self) -> None:
        path = ida_kernwin.ask_file(True, "*.ps1", "Export Dragon Reverse PowerShell probe")
        if not path:
            return
        text = self._powershell_probe_template()
        self._write_text(path, text)
        self.status.setText("Exported PowerShell probe: %s" % path)

    def export_cpp_harness(self) -> None:
        path = ida_kernwin.ask_file(True, "*.cpp", "Export Dragon Reverse C++ harness")
        if not path:
            return
        text = self._cpp_harness_template()
        self._write_text(path, text)
        self.status.setText("Exported C++ harness: %s" % path)

    def export_dynamic_manifest(self) -> None:
        path = ida_kernwin.ask_file(True, "*.json", "Export Dragon Reverse evidence manifest")
        if not path:
            return
        with open(path, "w", encoding="utf-8", newline="\n") as f:
            json.dump(self._dynamic_manifest(), f, indent=2)
        self.status.setText("Exported evidence manifest: %s" % path)

    def _dynamic_manifest(self) -> dict[str, Any]:
        meta = self.analyzer.meta or {
            "file": input_filename(),
            "path": input_path(),
            "sha256": input_sha256()
        }
        return {
            "target": {
                "file": meta.get("file", ""),
                "path": self.driver_path_edit.text().strip() or meta.get("path", ""),
                "sha256": meta.get("sha256", ""),
                "device_path": self.device_path_edit.text().strip(),
                "service_name": self.service_name_edit.text().strip(),
                "known_profile": meta.get("known_profile", {}),
                "known_profile_source": meta.get("known_profile_source", "")
            },
            "static_triage": {
                "top_correlations": self.analyzer.correlations[:20],
                "top_findings": [finding.__dict__ for finding in self.analyzer.findings[:80]],
                "top_functions": [
                    {
                        "ea": fn.ea,
                        "name": fn.name,
                        "score": fn.score,
                        "roles": sorted(fn.roles),
                        "families": sorted(fn.families),
                        "ioctls": fn.ioctls[:20],
                        "evidence": sorted(set(fn.evidence))[:40],
                        "pseudocode_hits": fn.pseudocode_hits,
                        "pseudocode_facts": fn.pseudocode_facts,
                        "proof_notes": fn.proof_notes,
                        "confidence_reason": fn.confidence_reason,
                        "review_status": fn.review_status
                    }
                    for fn in self.analyzer.functions[:40]
                ],
                "device_path_guesses": self._device_path_guesses(),
                "ioctl_candidates": self._ioctl_candidates()[:80]
            },
            "dynamic_evidence_plan": {
                "default_mode": "non-destructive",
                "required_context": [
                    "OS build and kernel version",
                    "test user SID, groups, privileges, elevation, and integrity level",
                    "driver file SHA256, Authenticode status, signer subject, file ACL",
                    "service state, start type, ImagePath, and service SDDL",
                    "device CreateFile access matrix as low-privileged user and elevated admin",
                    "direct-denial control for the privileged resource or operation",
                    "driver-mediated positive control only for reversible, case-specific tests"
                ],
                "negative_controls": [
                    "same low-privileged account cannot directly write HKLM service state",
                    "same low-privileged account cannot directly open protected process/token/section target with requested access",
                    "same low-privileged account cannot directly access equivalent firmware/MSR/physical-memory path",
                    "nonexistent or wrong device path fails with expected error"
                ],
                "positive_controls": [
                    "device opens with unexpectedly broad rights for low-privileged user",
                    "IOCTL handler reachability is proven with a reversible no-op/query operation when available",
                    "before/after state is captured only for reversible state changes",
                    "kernel debugger or ETW evidence confirms the suspected path without relying on a crash"
                ],
                "safety_gates": [
                    "PowerShell probe never calls DeviceIoControl",
                    "C++ harness requires --allow-deviceiocontrol and --i-understand-this-can-crash",
                    "no exploit payload is generated automatically",
                    "active IOCTL tests must be selected manually from the candidate list",
                    "C++ harness can emit JSONL evidence with case-id, buffer sizes, return code, GetLastError, and bytes_returned"
                ]
            }
        }

    def _write_text(self, path: str, text: str) -> None:
        with open(path, "w", encoding="utf-8", newline="\n") as f:
            f.write(text)

    def _device_path_guesses(self) -> list[str]:
        values: set[str] = set()
        known = self.analyzer.meta.get("known_profile", {}) if self.analyzer.meta else {}
        for path in known.get("device_paths", []) or []:
            if path:
                values.add(str(path))
        texts = [s for _ea, s in self.analyzer.critical_strings]
        for fn in self.analyzer.functions:
            texts.extend(fn.strings)
        for text in texts:
            for match in re.finditer(r"\\DosDevices\\([A-Za-z0-9_.-]+)", text):
                values.add(r"\\.\\%s" % match.group(1))
            for match in re.finditer(r"\\Device\\([A-Za-z0-9_.-]+)", text):
                values.add(r"\\.\\%s" % match.group(1))
        for text in self._file_device_strings():
            for match in re.finditer(r"\\DosDevices\\([A-Za-z0-9_.-]+)", text):
                values.add(r"\\.\\%s" % match.group(1))
            for match in re.finditer(r"\\Device\\([A-Za-z0-9_.-]+)", text):
                values.add(r"\\.\\%s" % match.group(1))
        return sorted(values)

    def _file_device_strings(self) -> list[str]:
        path = input_path()
        if not path or not os.path.exists(path):
            return []
        try:
            with open(path, "rb") as f:
                data = f.read()
        except Exception:
            return []
        out: set[str] = set()
        try:
            ascii_text = data.decode("latin1", "ignore")
            out.update(re.findall(r"\\(?:DosDevices|Device)\\[A-Za-z0-9_.-]+", ascii_text))
        except Exception:
            pass
        try:
            wide_text = data.decode("utf-16le", "ignore")
            out.update(re.findall(r"\\(?:DosDevices|Device)\\[A-Za-z0-9_.-]+", wide_text))
        except Exception:
            pass
        return sorted(out)

    def _ioctl_candidates(self) -> list[dict[str, Any]]:
        seen: set[tuple[int, int]] = set()
        rows: list[dict[str, Any]] = []
        for fn in self.analyzer.functions:
            for item in fn.ioctls:
                key = (int(item.get("value", 0)), int(item.get("ea", fn.ea)))
                if key in seen:
                    continue
                seen.add(key)
                row = dict(item)
                row["function_code"] = item.get("function_code", item.get("function", 0))
                row["function"] = fn.name
                row["function_ea"] = fn.ea
                rows.append(row)
        rows.sort(key=lambda r: (r.get("access") == "FILE_ANY_ACCESS", r.get("method") == "METHOD_NEITHER", r.get("value", 0)), reverse=True)
        return rows

    def _powershell_probe_template(self) -> str:
        device = self.device_path_edit.text().strip() or r"\\.\DeviceName"
        service = self.service_name_edit.text().strip() or os.path.splitext(input_filename())[0]
        driver = self.driver_path_edit.text().strip() or input_path()
        template = r'''param(
    [string]$DevicePath = "__DEVICE__",
    [string]$ServiceName = "__SERVICE__",
    [string]$DriverPath = "__DRIVER__",
    [string]$OutDir = ""
)

$ErrorActionPreference = "Continue"

if ($OutDir) {
    New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
    Start-Transcript -Path (Join-Path $OutDir "dragon_reverse_probe_transcript.txt") -Force | Out-Null
}

Write-Host "== Dragon Reverse non-destructive dynamic probe =="
Write-Host "DevicePath: $DevicePath"
Write-Host "ServiceName: $ServiceName"
Write-Host "DriverPath: $DriverPath"
Write-Host ""

Write-Host "== OS context =="
try {
    Get-ComputerInfo | Select-Object WindowsProductName, WindowsVersion, OsBuildNumber, OsHardwareAbstractionLayer
} catch {
    cmd /c ver
}
Write-Host ""

Write-Host "== Token context =="
whoami /user
whoami /groups
whoami /priv
try {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($id)
    Write-Host ("IsAdministrator: {0}" -f $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
} catch {}
Write-Host ""

if ($DriverPath -and (Test-Path -LiteralPath $DriverPath)) {
    Write-Host "== Driver file =="
    Get-Item -LiteralPath $DriverPath | Select-Object FullName, Length, LastWriteTime
    Get-FileHash -Algorithm SHA256 -LiteralPath $DriverPath
    Get-AuthenticodeSignature -LiteralPath $DriverPath | Select-Object Status, StatusMessage, @{Name='Subject';Expression={$_.SignerCertificate.Subject}}
    Get-Acl -LiteralPath $DriverPath | Select-Object Path, Owner, Group, AccessToString
    Write-Host ""
}

if ($ServiceName -and $ServiceName -ne "<set service name>") {
    Write-Host "== Service state and descriptor =="
    try { Get-CimInstance Win32_SystemDriver -Filter "Name='$ServiceName'" | Select-Object Name, State, StartMode, PathName, ServiceType } catch {}
    try { & sc.exe query $ServiceName } catch {}
    try { & sc.exe qc $ServiceName } catch {}
    try { & sc.exe sdshow $ServiceName } catch {}
    Write-Host ""

    Write-Host "== Service registry access check =="
    $keyPath = "SYSTEM\CurrentControlSet\Services\$ServiceName"
    $readKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($keyPath, $false)
    if ($readKey) {
        Write-Host "HKLM\$keyPath READ: OK"
        $readKey.GetValueNames() | ForEach-Object {
            try { Write-Host "  $_ = $($readKey.GetValue($_))" } catch {}
        }
        $readKey.Close()
    } else {
        Write-Host "HKLM\$keyPath READ: FAILED"
    }
    try {
        $writeKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($keyPath, $true)
        if ($writeKey) {
            Write-Host "HKLM\$keyPath KEY_SET_VALUE-like writable open: OK (no values written)"
            $writeKey.Close()
        } else {
            Write-Host "HKLM\$keyPath KEY_SET_VALUE-like writable open: DENIED/NULL"
        }
    } catch {
        Write-Host "HKLM\$keyPath KEY_SET_VALUE-like writable open: $($_.Exception.Message)"
    }
    Write-Host ""
}

Add-Type @'
using System;
using System.Runtime.InteropServices;

public static class DragonReverseNative
{
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    public static extern IntPtr CreateFileW(
        string lpFileName,
        UInt32 dwDesiredAccess,
        UInt32 dwShareMode,
        IntPtr lpSecurityAttributes,
        UInt32 dwCreationDisposition,
        UInt32 dwFlagsAndAttributes,
        IntPtr hTemplateFile);

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool CloseHandle(IntPtr hObject);
}
'@

Write-Host "== CreateFile access matrix =="
$OPEN_EXISTING = 3
$FILE_SHARE_READ = 1
$FILE_SHARE_WRITE = 2
$FILE_SHARE_DELETE = 4
$GENERIC_READ = [UInt32]0x80000000
$GENERIC_WRITE = [UInt32]0x40000000
$WRITE_DAC = [UInt32]0x00040000
$cases = @(
    @{Name="0 metadata"; Access=[UInt32]0},
    @{Name="GENERIC_READ"; Access=$GENERIC_READ},
    @{Name="GENERIC_WRITE"; Access=$GENERIC_WRITE},
    @{Name="GENERIC_READ|GENERIC_WRITE"; Access=($GENERIC_READ -bor $GENERIC_WRITE)},
    @{Name="WRITE_DAC"; Access=$WRITE_DAC}
)
foreach ($case in $cases) {
    $h = [DragonReverseNative]::CreateFileW($DevicePath, [UInt32]$case.Access, [UInt32]($FILE_SHARE_READ -bor $FILE_SHARE_WRITE -bor $FILE_SHARE_DELETE), [IntPtr]::Zero, [UInt32]$OPEN_EXISTING, [UInt32]0, [IntPtr]::Zero)
    $err = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
    if ($h.ToInt64() -eq -1) {
        Write-Host ("{0,-28} DENIED/FAILED err={1}" -f $case.Name, $err)
    } else {
        Write-Host ("{0,-28} OK handle=0x{1:X}" -f $case.Name, $h.ToInt64())
        [void][DragonReverseNative]::CloseHandle($h)
    }
}

Write-Host ""
Write-Host "No DeviceIoControl calls were made by this PowerShell probe."
Write-Host "Use the exported C++ harness only for explicitly selected, reversible test cases."
if ($OutDir) {
    Stop-Transcript | Out-Null
}
'''
        return (template
                .replace("__DEVICE__", device.replace('"', '`"'))
                .replace("__SERVICE__", service.replace('"', '`"'))
                .replace("__DRIVER__", driver.replace('"', '`"')))

    def _cpp_harness_template(self) -> str:
        device = self.device_path_edit.text().strip() or r"\\.\DeviceName"
        ioctls = self._ioctl_candidates()
        ioctl_lines = []
        for item in ioctls[:40]:
            ioctl_lines.append("  // %s %s %s at %s in %s" % (
                item.get("hex", ""),
                item.get("access", ""),
                item.get("method", ""),
                ea_text(item.get("ea", idc.BADADDR)),
                item.get("function", "")))
        ioctl_comment = "\n".join(ioctl_lines) if ioctl_lines else "  // No decoded IOCTL candidates were available when this harness was exported."
        template = r'''// Dragon Reverse controlled dynamic harness.
// Default mode is non-destructive: CreateFile access matrix only.
//
// Build with Visual Studio Developer Command Prompt:
//   cl /EHsc /std:c++17 dragon_reverse_harness.cpp
//
// Active DeviceIoControl is disabled unless both flags are present:
//   --allow-deviceiocontrol --i-understand-this-can-crash --ioctl 0xXXXXXXXX
//
// This harness does not generate payloads. If active IOCTL mode is enabled, it
// sends only user-provided hex bytes, a zero-length input buffer, or an
// explicitly requested zero-filled input size. Use --jsonl to preserve evidence.

#include <windows.h>
#include <stdint.h>

#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

static std::wstring widen(const std::string& s) {
    int needed = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
    std::wstring out(needed ? needed - 1 : 0, L'\0');
    if (needed > 1) MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, out.data(), needed);
    return out;
}

static bool parse_u32(const std::string& s, uint32_t& out) {
    char* end = nullptr;
    unsigned long v = strtoul(s.c_str(), &end, 0);
    if (!end || *end != '\0') return false;
    out = static_cast<uint32_t>(v);
    return true;
}

static std::vector<uint8_t> parse_hex_bytes(const std::string& s) {
    std::vector<uint8_t> out;
    std::string compact;
    for (char c : s) {
        if (c == ' ' || c == ':' || c == '-' || c == ',') continue;
        compact.push_back(c);
    }
    if (compact.size() % 2 != 0) compact = "0" + compact;
    for (size_t i = 0; i + 1 < compact.size(); i += 2) {
        std::string byte_s = compact.substr(i, 2);
        out.push_back(static_cast<uint8_t>(strtoul(byte_s.c_str(), nullptr, 16)));
    }
    return out;
}

static void print_last_error(const char* label) {
    DWORD err = GetLastError();
    std::cout << label << " err=" << err << std::endl;
}

static std::string json_escape(const std::string& s) {
    std::ostringstream os;
    for (char c : s) {
        switch (c) {
        case '\\': os << "\\\\"; break;
        case '"': os << "\\\""; break;
        case '\n': os << "\\n"; break;
        case '\r': os << "\\r"; break;
        case '\t': os << "\\t"; break;
        default:
            if (static_cast<unsigned char>(c) < 0x20) os << "\\u00" << std::hex << std::setw(2) << std::setfill('0') << int(static_cast<unsigned char>(c));
            else os << c;
        }
    }
    return os.str();
}

static std::string now_iso8601_utc() {
    SYSTEMTIME st;
    GetSystemTime(&st);
    char buf[64];
    sprintf_s(buf, "%04u-%02u-%02uT%02u:%02u:%02u.%03uZ",
              st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
    return std::string(buf);
}

static std::string hex_preview(const std::vector<uint8_t>& bytes, DWORD count) {
    std::ostringstream os;
    DWORD available = static_cast<DWORD>(bytes.size());
    DWORD limit = count;
    if (limit > available) limit = available;
    if (limit > 64) limit = 64;
    for (DWORD i = 0; i < limit; ++i) {
        if (i) os << " ";
        os << std::uppercase << std::hex << std::setw(2) << std::setfill('0') << int(bytes[i]);
    }
    return os.str();
}

static HANDLE open_device(const std::wstring& device, DWORD access) {
    return CreateFileW(
        device.c_str(),
        access,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);
}

static void access_matrix(const std::wstring& device) {
    struct Case { const char* name; DWORD access; };
    Case cases[] = {
        {"0 metadata", 0},
        {"GENERIC_READ", GENERIC_READ},
        {"GENERIC_WRITE", GENERIC_WRITE},
        {"GENERIC_READ|GENERIC_WRITE", GENERIC_READ | GENERIC_WRITE},
        {"WRITE_DAC", WRITE_DAC}
    };
    std::cout << "== CreateFile access matrix ==" << std::endl;
    for (const auto& c : cases) {
        SetLastError(0);
        HANDLE h = open_device(device, c.access);
        if (h == INVALID_HANDLE_VALUE) {
            std::cout << c.name << " FAILED err=" << GetLastError() << std::endl;
        } else {
            std::cout << c.name << " OK" << std::endl;
            CloseHandle(h);
        }
    }
}

int main(int argc, char** argv) {
    std::string device_utf8 = "__DEVICE__";
    bool allow_ioctl = false;
    bool understand = false;
    uint32_t ioctl = 0;
    bool have_ioctl = false;
    DWORD open_access = GENERIC_READ;
    DWORD out_size = 0;
    uint32_t in_size = 0;
    bool have_in_size = false;
    int repeat = 1;
    DWORD sleep_ms = 0;
    std::string jsonl_path;
    std::string case_id = "manual";
    std::vector<uint8_t> in_bytes;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--device" && i + 1 < argc) device_utf8 = argv[++i];
        else if (arg == "--allow-deviceiocontrol") allow_ioctl = true;
        else if (arg == "--i-understand-this-can-crash") understand = true;
        else if (arg == "--ioctl" && i + 1 < argc) have_ioctl = parse_u32(argv[++i], ioctl);
        else if (arg == "--open-access" && i + 1 < argc) parse_u32(argv[++i], open_access);
        else if (arg == "--in-hex" && i + 1 < argc) in_bytes = parse_hex_bytes(argv[++i]);
        else if (arg == "--in-size" && i + 1 < argc) {
            uint32_t tmp = 0;
            if (parse_u32(argv[++i], tmp)) {
                in_size = tmp;
                have_in_size = true;
            }
        }
        else if (arg == "--out-size" && i + 1 < argc) {
            uint32_t tmp = 0;
            if (parse_u32(argv[++i], tmp)) out_size = tmp;
        } else if (arg == "--repeat" && i + 1 < argc) {
            uint32_t tmp = 0;
            if (parse_u32(argv[++i], tmp)) {
                if (tmp > 1000) tmp = 1000;
                repeat = static_cast<int>(tmp);
            }
        } else if (arg == "--sleep-ms" && i + 1 < argc) {
            uint32_t tmp = 0;
            if (parse_u32(argv[++i], tmp)) sleep_ms = tmp;
        } else if (arg == "--jsonl" && i + 1 < argc) {
            jsonl_path = argv[++i];
        } else if (arg == "--case-id" && i + 1 < argc) {
            case_id = argv[++i];
        } else if (arg == "--help") {
            std::cout << "Usage: dragon_reverse_harness.exe [--device \\\\.\\Name] [--jsonl evidence.jsonl] [--case-id CASE]"
                      << " [--allow-deviceiocontrol --i-understand-this-can-crash --ioctl 0xXXXXXXXX]"
                      << " [--in-hex 0011 | --in-size N] [--out-size N] [--repeat N] [--sleep-ms N]" << std::endl;
            return 0;
        }
    }

    if (in_bytes.empty() && have_in_size && in_size > 0) {
        in_bytes.assign(in_size, 0);
    }

    std::wstring device = widen(device_utf8);
    std::wcout << L"Device: " << device << std::endl;
    access_matrix(device);

    std::cout << std::endl << "== IOCTL candidates exported by IDA ==" << std::endl;
__IOCTL_COMMENT__

    if (!allow_ioctl || !understand || !have_ioctl) {
        std::cout << std::endl << "DeviceIoControl not executed. Provide --allow-deviceiocontrol --i-understand-this-can-crash --ioctl 0xXXXXXXXX for a selected reversible test." << std::endl;
        return 0;
    }

    HANDLE h = open_device(device, open_access);
    if (h == INVALID_HANDLE_VALUE) {
        print_last_error("Open for DeviceIoControl failed");
        return 2;
    }

    std::ofstream jsonl;
    if (!jsonl_path.empty()) {
        jsonl.open(jsonl_path, std::ios::out | std::ios::app);
    }

    int final_rc = 0;
    for (int iter = 0; iter < repeat; ++iter) {
        std::vector<uint8_t> out(out_size);
        DWORD bytes_returned = 0;
        SetLastError(0);
        BOOL ok = DeviceIoControl(
            h,
            ioctl,
            in_bytes.empty() ? nullptr : in_bytes.data(),
            static_cast<DWORD>(in_bytes.size()),
            out.empty() ? nullptr : out.data(),
            static_cast<DWORD>(out.size()),
            &bytes_returned,
            nullptr);
        DWORD err = GetLastError();
        std::string out_preview = hex_preview(out, bytes_returned);
        std::cout << "DeviceIoControl case=" << case_id
                  << " iter=" << iter
                  << " ioctl=0x" << std::hex << ioctl << std::dec
                  << " ok=" << (ok ? "true" : "false")
                  << " err=" << err
                  << " in_size=" << in_bytes.size()
                  << " out_size=" << out.size()
                  << " bytes_returned=" << bytes_returned << std::endl;
        if (!out_preview.empty()) {
            std::cout << "OutputPreview: " << out_preview << std::endl;
        }
        if (jsonl.is_open()) {
            jsonl << "{"
                  << "\"ts\":\"" << now_iso8601_utc() << "\","
                  << "\"case_id\":\"" << json_escape(case_id) << "\","
                  << "\"device\":\"" << json_escape(device_utf8) << "\","
                  << "\"iteration\":" << iter << ","
                  << "\"ioctl\":\"0x" << std::uppercase << std::hex << ioctl << std::dec << "\","
                  << "\"open_access\":" << open_access << ","
                  << "\"ok\":" << (ok ? "true" : "false") << ","
                  << "\"last_error\":" << err << ","
                  << "\"in_size\":" << in_bytes.size() << ","
                  << "\"out_size\":" << out.size() << ","
                  << "\"bytes_returned\":" << bytes_returned << ","
                  << "\"output_preview_hex\":\"" << json_escape(out_preview) << "\""
                  << "}" << std::endl;
        }
        if (!ok) final_rc = 1;
        if (sleep_ms && iter + 1 < repeat) {
            Sleep(sleep_ms);
        }
    }
    CloseHandle(h);
    return final_rc;
}
'''
        return (template
                .replace("__DEVICE__", device.replace("\\", "\\\\").replace('"', '\\"'))
                .replace("__IOCTL_COMMENT__", ioctl_comment))

    def update_dashboard(self) -> None:
        meta = self.analyzer.meta or {
            "file": input_filename(),
            "path": input_path(),
            "sha256": input_sha256(),
            "function_count": len(list(idautils.Functions())),
            "hexrays": False
        }
        known = meta.get("known_profile") or {}
        sev_counts: dict[str, int] = {}
        for finding in self.analyzer.findings:
            sev_counts[finding.severity] = sev_counts.get(finding.severity, 0) + 1
        html = [
            "<h2>Dragon Reverse</h2>",
            "<p><b>File:</b> %s<br><b>Path:</b> %s<br><b>SHA256:</b> %s</p>" % (
                self._html(meta.get("file", "")), self._html(meta.get("path", "")), self._html(meta.get("sha256", ""))),
            "<p><b>Functions:</b> %s<br><b>Hex-Rays:</b> %s</p>" % (
                meta.get("function_count", ""), "available" if meta.get("hexrays") else "not checked/available"),
            "<p><b>Analysis mode:</b> %s<br><b>Scan mode:</b> %s<br><b>Pseudocode bodies:</b> %s<br><b>Decompile failures:</b> %s<br><b>Ordinal imports:</b> %s</p>" % (
                self._html(meta.get("analysis_mode", self.current_analysis_mode())),
                self._html(meta.get("scan_mode", "not run")),
                self._html(meta.get("pseudocode_decompiled", 0)),
                self._html(meta.get("pseudocode_failures", 0)),
                self._html(meta.get("ordinal_imports", 0))),
            "<h3>Summary</h3>",
            "<ul>",
            "<li>Findings: %d</li>" % len(self.analyzer.findings),
            "<li>Primitive chains: %d</li>" % len(self.analyzer.primitive_chains),
            "<li>Correlations: %d</li>" % len(self.analyzer.correlations),
            "<li>LOLDrivers matches: %d</li>" % len(self.lol_matches)
        ]
        for sev in ("Critical", "High", "Medium", "Low", "Info"):
            if sev_counts.get(sev):
                html.append("<li>%s</li>" % self._severity_badge_html(sev, sev_counts[sev]))
        if self.analyzer.primitive_chains:
            chain_types: dict[str, int] = {}
            for chain in self.analyzer.primitive_chains:
                chain_types[chain.chain_type] = chain_types.get(chain.chain_type, 0) + 1
            html.append("<li>Chain types: %s</li>" % self._html(", ".join("%s=%d" % (k, v) for k, v in sorted(chain_types.items()))))
        statuses: dict[str, int] = {}
        for item in list(self.analyzer.findings) + list(self.analyzer.functions) + list(self.analyzer.primitive_chains):
            status = getattr(item, "review_status", "")
            if status:
                statuses[status] = statuses.get(status, 0) + 1
        if statuses:
            html.append("<li>Review statuses: %s</li>" % self._html(", ".join("%s=%d" % (k, v) for k, v in sorted(statuses.items()))))
        html.append("</ul>")
        if known:
            extras = []
            if known.get("primitives"):
                extras.append("<b>Primitives:</b> %s" % self._html(", ".join(known.get("primitives", []))))
            if known.get("cves"):
                extras.append("<b>CVE:</b> %s" % self._html(", ".join(known.get("cves", []))))
            if known.get("projects"):
                extras.append("<b>Refs/tools:</b> %s" % self._html(", ".join(known.get("projects", []))))
            if meta.get("known_profile_source") == "filename_seed":
                extras.append("<b>Match:</b> filename-only seed, confirm hash/version before reporting as known vulnerable.")
            html += [
                "<h3>Known local profile</h3>",
                "<p><b>%s</b><br>%s<br>%s<br>%s</p>" % (
                    self._html(known.get("name", "")),
                    self._html(known.get("family", "")),
                    self._html(known.get("notes", "")),
                    "<br>".join(extras))
            ]
        if self.lol_matches:
            html.append("<h3>LOLDrivers API matches</h3><ul>")
            for match in self.lol_matches[:10]:
                html.append("<li>%s - %s - %s</li>" % (
                    self._html(str(match.get("filename", ""))),
                    self._html(str(match.get("category", ""))),
                    self._html(str(match.get("description", ""))[:220])))
            html.append("</ul>")
        html += [
            "<h3>Workflow</h3>",
            "<p>Use the findings as a manual review queue: start from device ACLs and IOCTL dispatchers, then follow paths into physical memory, MSR, registry, MDL, and user-pointer primitives.</p>"
        ]
        self.dashboard.setHtml("\n".join(html))

    def populate_knowledge(self) -> None:
        lines = ["<h2>Knowledge base</h2>"]
        lines.append("<h3>Families</h3><ul>")
        for family in self.rules.get("families", []):
            lines.append("<li><b>%s</b><br>Signals: %s<br>Review: %s</li>" % (
                self._html(family.get("name", family.get("id", ""))),
                self._html(", ".join(family.get("signals", []))),
                self._html(family.get("review", ""))))
        lines.append("</ul>")
        lines.append("<h3>Known local hashes</h3><ul>")
        for sha, profile in sorted(self.rules.get("known_hashes", {}).items(), key=lambda kv: kv[1].get("name", "")):
            lines.append("<li><b>%s</b> - %s<br><code>%s</code></li>" % (
                self._html(profile.get("name", "")),
                self._html(profile.get("family", "")),
                self._html(sha)))
        lines.append("</ul>")
        profiles = self.rules.get("filename_profiles", {})
        if isinstance(profiles, dict) and profiles:
            lines.append("<h3>BYOVD filename profiles</h3><ul>")
            for key, profile in sorted(profiles.items(), key=lambda kv: str(kv[0]).lower()):
                lines.append("<li><b>%s</b> - %s<br>Primitives: %s<br>CVE: %s<br>Refs: %s</li>" % (
                    self._html(profile.get("name", key)),
                    self._html(profile.get("family", "")),
                    self._html(", ".join(profile.get("primitives", []) or [])),
                    self._html(", ".join(profile.get("cves", []) or [])),
                    self._html(", ".join(profile.get("projects", []) or []))))
            lines.append("</ul>")
        lol = self.rules.get("lol_drivers", {})
        lines.append("<h3>LOLDrivers</h3>")
        lines.append("<p>API: <code>%s</code><br>Site: <a href='%s'>%s</a></p>" % (
            self._html(lol.get("api_json", "")),
            self._html(lol.get("site", "")),
            self._html(lol.get("site", ""))))
        self.knowledge_text.setHtml("\n".join(lines))

    def fetch_loldrivers(self) -> None:
        url = self.rules.get("lol_drivers", {}).get("api_json", "https://www.loldrivers.io/api/drivers.json")
        sha256 = (self.analyzer.meta.get("sha256") if self.analyzer.meta else input_sha256()).lower()
        if not sha256:
            self.status.setText("No input SHA256 available.")
            return
        self.status.setText("Fetching LOLDrivers metadata...")
        QtWidgets.QApplication.processEvents()
        try:
            with urllib.request.urlopen(url, timeout=15) as response:
                raw = response.read().decode("utf-8", "replace")
            rows = self._parse_loldrivers_payload(raw)
            matches = []
            for row in rows:
                samples = row.get("KnownVulnerableSamples") or row.get("Samples") or []
                if isinstance(samples, dict):
                    samples = [samples]
                for sample in samples:
                    if not isinstance(sample, dict):
                        continue
                    s256 = str(sample.get("SHA256") or sample.get("sha256") or "").lower()
                    if s256 == sha256:
                        matches.append({
                            "filename": sample.get("Filename") or sample.get("OriginalFilename") or row.get("Name") or "",
                            "category": row.get("Category") or row.get("category") or "",
                            "description": row.get("Description") or row.get("description") or row.get("Name") or "",
                            "verified": row.get("Verified") or row.get("verified") or "",
                            "raw": row
                        })
            self.lol_matches = matches
            if matches:
                self.status.setText("LOLDrivers match found: %d" % len(matches))
                for match in matches:
                    self.analyzer.findings.insert(0, Finding(
                        severity="Critical",
                        score=85,
                        ea=idc.BADADDR,
                        function="binary",
                        category="LOLDrivers known driver match",
                        signal=str(match.get("filename", "")),
                        evidence="%s - %s" % (match.get("category", ""), match.get("description", "")),
                        review="Treat this as known-risk. Compare the matched profile against unknown drivers for similar primitives.",
                        family="loldrivers",
                        confidence_reason="exact SHA256 match from LOLDrivers payload"
                    ))
                self.populate_all()
            else:
                self.status.setText("No exact SHA256 match in LOLDrivers payload.")
                self.update_dashboard()
        except Exception as exc:
            self.status.setText("LOLDrivers fetch failed: %s" % exc)
            ida_kernwin.msg("[DragonReverse] LOLDrivers fetch failed\n%s\n" % traceback.format_exc())

    def _parse_loldrivers_payload(self, raw: str) -> list[dict[str, Any]]:
        raw = raw.strip()
        if not raw:
            return []
        if raw.startswith("["):
            data = json.loads(raw)
            return data if isinstance(data, list) else []
        rows: list[dict[str, Any]] = []
        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
                if isinstance(item, dict):
                    rows.append(item)
            except Exception:
                continue
        return rows

    def decompile_current(self) -> None:
        ea = ida_kernwin.get_screen_ea()
        self.show_pseudocode_for_ea(ea)

    def decompile_selected_finding(self) -> None:
        rows = self.findings_table.selectionModel().selectedRows()
        if not rows:
            self.decompile_current()
            return
        row = rows[0].row()
        item = self.findings_table.item(row, 3)
        ea = item.data(USER_ROLE) if item else idc.BADADDR
        self.show_pseudocode_for_ea(int(ea) if ea is not None else -1)

    def show_pseudocode_for_ea(self, ea: int) -> None:
        if ea == idc.BADADDR or ea < 0:
            self.pseudo_text.setPlainText("No function address selected.")
            self.tabs.setCurrentWidget(self.pseudo_text.parentWidget())
            return
        text = self.analyzer.decompile_function(ea)
        if not text:
            text = "Hex-Rays decompiler is not available or this address is not in a function."
        elif not text.startswith("Decompile failed"):
            text = self._pseudocode_profile_text(ea, text) + "\n\n" + text
        self.pseudo_text.setPlainText(text)
        self.tabs.setCurrentWidget(self.pseudo_text.parentWidget())

    def _function_summary_for_ea(self, ea: int) -> FunctionSummary | None:
        func = ida_funcs.get_func(ea)
        start = func.start_ea if func else ea
        for summary in self.analyzer.functions:
            if summary.ea == start:
                return summary
        return None

    def _pseudocode_profile_text(self, ea: int, text: str) -> str:
        summary = self._function_summary_for_ea(ea)
        pseudo_hits = self.analyzer._pseudocode_hits(text)
        pseudo_facts = self.analyzer._pseudocode_facts(text)
        pseudo_roles = self.analyzer._roles_from_text(text)
        if summary and pseudo_roles:
            summary.roles.update(pseudo_roles)
            summary.pseudocode_facts = pseudo_facts
            summary.proof_notes = self.analyzer._pseudocode_proof_notes(pseudo_facts)
        roles = sorted((summary.roles if summary else set()) | pseudo_roles)
        families = sorted(summary.families) if summary else []
        ioctls = summary.ioctls if summary else []
        evidence = sorted(set(summary.evidence))[:30] if summary else []
        lines = [
            "Dragon Reverse function profile",
            "  EA: %s" % ea_text(summary.ea if summary else ea),
            "  Function: %s" % (summary.name if summary else safe_name(ea)),
            "  Roles: %s" % (", ".join(roles) if roles else "not inferred"),
            "  Families: %s" % (", ".join(families) if families else "none"),
            "  Pseudocode hits: %s" % (", ".join(pseudo_hits) if pseudo_hits else "none"),
            "  Pseudocode facts: %s" % self.analyzer._pseudocode_fact_evidence(pseudo_facts),
            "  IOCTLs: %s" % (", ".join("%s %s %s" % (i["hex"], i["access"], i["method"]) for i in ioctls[:12]) if ioctls else "none decoded"),
            "  Evidence: %s" % (", ".join(evidence) if evidence else "none"),
            "",
            "Review checklist",
            "  - Color legend in this tab: red=sensitive sink, blue=user source/length, green=guard/caller mode, purple=IOCTL, amber=missing-gate warning.",
            "  - Identify caller-controlled fields before each privileged primitive.",
            "  - Confirm caller mode, desired access, privilege gates, and object type checks.",
            "  - Compare METHOD_NEITHER/user-pointer paths against probing, try/except, and length validation.",
            "  - For FILE_ANY_ACCESS IOCTLs, verify whether the operation should require read/write access or explicit privilege.",
            "  - For dynamic proof, prefer direct-denial vs driver-mediated reachability before any active IOCTL test."
        ]
        proof_notes = self.analyzer._pseudocode_proof_notes(pseudo_facts)
        if proof_notes:
            lines.extend(["", "Pseudo-code proof notes"])
            lines.extend("  - " + note for note in proof_notes)
        return "\n".join(lines)

    def jump_from_table(self, table: QtWidgets.QTableWidget, row: int, ea_col: int) -> None:
        item = table.item(row, ea_col)
        if not item:
            return
        ea = item.data(USER_ROLE)
        if ea is None:
            text = item.text()
            try:
                ea = int(text, 16)
            except Exception:
                return
        target = int(ea)
        if target != idc.BADADDR and target >= 0:
            ida_kernwin.jumpto(target)

    def update_details_from_finding(self) -> None:
        rows = self.findings_table.selectionModel().selectedRows()
        if not rows:
            return
        idx = rows[0].row()
        if idx >= len(self.analyzer.findings):
            return
        f = self.analyzer.findings[idx]
        self.details.setPlainText(
            "Severity: %s\nScore: %d\nStatus: %s\nEA: %s\nFunction: %s\nCategory: %s\nSignal: %s\nConfidence reason: %s\nEvidence: %s\nReview: %s" %
            (f.severity, f.score, f.review_status, ea_text(f.ea), f.function, f.category, f.signal, f.confidence_reason, f.evidence, f.review)
        )

    def update_details_from_function(self) -> None:
        rows = self.funcs_table.selectionModel().selectedRows()
        if not rows:
            return
        idx = rows[0].row()
        if idx >= len(self.analyzer.functions):
            return
        fn = self.analyzer.functions[idx]
        self.details.setPlainText(
            "Function: %s\nEA: %s\nScore: %d\nStatus: %s\nConfidence reason: %s\nRoles: %s\nFamilies: %s\nCallers: %s\nCallees: %s\nCalls/imports: %s\nIOCTLs: %s\nEvidence: %s" %
            (
                fn.name,
                ea_text(fn.ea),
                fn.score,
                fn.review_status,
                fn.confidence_reason,
                ", ".join(sorted(fn.roles)),
                ", ".join(sorted(fn.families)),
                ", ".join(sorted(fn.callers)[:30]),
                ", ".join(sorted(fn.callees)[:30]),
                ", ".join(sorted(fn.calls)[:30]),
                ", ".join("%s %s %s" % (i["hex"], i["access"], i["method"]) for i in fn.ioctls[:20]),
                ", ".join(sorted(set(fn.evidence))[:40])
            )
        )

    def update_details_from_chain(self) -> None:
        rows = self.chains_table.selectionModel().selectedRows()
        if not rows:
            return
        idx = rows[0].row()
        if idx >= len(self.analyzer.primitive_chains):
            return
        chain = self.analyzer.primitive_chains[idx]
        self.details.setPlainText(
            "Chain: %s -> %s\nType: %s\nStatus: %s\nSeverity: %s\nConfidence: %d\nConfidence reason: %s\nPrimitive: %s\nAccess surface: %s\nEvidence: %s\nProof focus: %s" %
            (
                chain.entry,
                chain.target,
                chain.chain_type,
                chain.review_status,
                chain.severity,
                chain.confidence,
                chain.confidence_reason,
                chain.primitive,
                chain.access_surface,
                chain.evidence,
                chain.proof_focus
            )
        )

    def update_details_from_correlation(self) -> None:
        rows = self.correlation_table.selectionModel().selectedRows()
        if not rows:
            return
        idx = rows[0].row()
        if idx >= len(self.analyzer.correlations):
            return
        row = self.analyzer.correlations[idx]
        funcs = "\n".join("  %s %s score=%s roles=%s" % (
            ea_text(f["ea"]), f["name"], f["score"], ", ".join(f.get("roles", []))) for f in row.get("functions", []))
        evidence = "\n".join("  " + str(e) for e in row.get("evidence", []))
        self.details.setPlainText(
            "Family: %s\nSeverity: %s\nConfidence: %s\nConfidence reason: %s\nRoles: %s\nReview: %s\nFunctions:\n%s\nEvidence:\n%s" %
            (row.get("name", ""), row.get("severity", ""), row.get("confidence", ""), row.get("confidence_reason", ""), ", ".join(row.get("roles", [])), row.get("review", ""), funcs, evidence)
        )

    def export_json(self) -> None:
        path = ida_kernwin.ask_file(True, "*.json", "Export Dragon Reverse JSON")
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(self.analyzer.as_json(), f, indent=2)
            self.status.setText("Exported JSON: %s" % path)
        except Exception as exc:
            self.status.setText("Export failed: %s" % exc)

    def export_markdown(self) -> None:
        path = ida_kernwin.ask_file(True, "*.md", "Export Dragon Reverse Markdown")
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(self.analyzer.markdown_report())
            self.status.setText("Exported Markdown: %s" % path)
        except Exception as exc:
            self.status.setText("Export failed: %s" % exc)

    def export_full_report(self) -> None:
        if self.analysis_running:
            self.status.setText("Analysis already running; full report export is waiting for a clean analyzer state.")
            return
        path = ida_kernwin.ask_file(True, "*.json", "Export Dragon Reverse full report (.json or .txt)")
        if not path:
            return
        try:
            if not self._ensure_analysis_for_export():
                return
            self.populate_dynamic_plan()
            report = self._complete_report()
            ext = os.path.splitext(path)[1].lower()
            with open(path, "w", encoding="utf-8", newline="\n") as f:
                if ext == ".txt":
                    f.write(self._complete_text_report(report))
                else:
                    json.dump(report, f, indent=2)
            self.status.setText("Exported full report: %s" % path)
        except Exception as exc:
            self.status.setText("Full report export failed: %s" % exc)
            ida_kernwin.msg("[DragonReverse] Full report export failed\n%s\n" % traceback.format_exc())

    def _ensure_analysis_for_export(self) -> bool:
        if self.analyzer.meta and self.analyzer.meta.get("full_scan"):
            return True
        if self.analysis_running:
            self.status.setText("Analysis already running; full report not exported.")
            return False
        self._set_analysis_busy(True, "Running Full Scan before full report export...")
        try:
            self.analyzer = DragonAnalyzer(self.rules, self.current_analysis_mode())
            self.analyzer.run(include_pseudocode=True, full_scan=True)
            self.populate_all()
            return True
        except Exception:
            self.status.setText("Full Scan failed; full report not exported.")
            ida_kernwin.msg("[DragonReverse] Full Scan before full report failed\n%s\n" % traceback.format_exc())
            return False
        finally:
            self._set_analysis_busy(False)

    def _generated_c_structs_for_report(self) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        for fn in self.analyzer.functions:
            fields = fn.pseudocode_facts.get("ioctl_struct_fields") or []
            if not fields:
                continue
            struct_name = "%s_IOCTL_REQUEST" % self._safe_c_ident(fn.name).upper()
            rows.append({
                "ea": fn.ea,
                "ea_text": ea_text(fn.ea),
                "function": fn.name,
                "field_count": len(fields),
                "fields": fields,
                "c_struct": self._c_struct_from_fields(fields, struct_name)
            })
            if len(rows) >= 40:
                break
        return rows

    def _complete_report(self) -> dict[str, Any]:
        analyzer_json = self.analyzer.as_json()
        complete_functions = []
        for fn in self.analyzer.functions:
            complete_functions.append({
                "ea": fn.ea,
                "ea_text": ea_text(fn.ea),
                "name": fn.name,
                "score": fn.score,
                "roles": sorted(fn.roles),
                "families": sorted(fn.families),
                "calls": sorted(fn.calls),
                "callers": sorted(fn.callers),
                "callees": sorted(fn.callees),
                "mnemonics": sorted(fn.mnemonics),
                "strings": sorted(fn.strings),
                "ioctls": fn.ioctls,
                "evidence": sorted(set(fn.evidence)),
                "pseudocode_hits": fn.pseudocode_hits,
                "pseudocode_facts": fn.pseudocode_facts,
                "proof_notes": fn.proof_notes,
                "confidence_reason": fn.confidence_reason,
                "review_status": fn.review_status
            })
        return {
            "report_type": "Dragon Reverse complete evidence report",
            "generated_utc": datetime.now(timezone.utc).isoformat(),
            "target": analyzer_json.get("meta", {}),
            "summary": {
                "findings": len(self.analyzer.findings),
                "functions": len(self.analyzer.functions),
                "primitive_chains": len(self.analyzer.primitive_chains),
                "correlations": len(self.analyzer.correlations),
                "critical_strings": len(self.analyzer.critical_strings),
                "lol_matches": len(self.lol_matches),
                "scan_mode": (self.analyzer.meta or {}).get("scan_mode", ""),
                "analysis_mode": (self.analyzer.meta or {}).get("analysis_mode", self.current_analysis_mode()),
                "full_scan": bool((self.analyzer.meta or {}).get("full_scan")),
                "pseudocode_decompiled": len(self.analyzer.pseudocode_by_ea),
                "pseudocode_failures": len(self.analyzer.pseudocode_failures),
                "decompile_cache_entries": int((self.analyzer.meta or {}).get("decompile_cache_entries", 0)),
                "decompile_cache_hits": int((self.analyzer.meta or {}).get("decompile_cache_hits", 0)),
                "ordinal_imports": int((self.analyzer.meta or {}).get("ordinal_imports", 0)),
                "hexrays_available": bool(self.analyzer.meta.get("hexrays")) if self.analyzer.meta else False
            },
            "known_profile": (self.analyzer.meta or {}).get("known_profile", {}),
            "lol_matches": self.lol_matches,
            "primitive_chains": [chain.__dict__ for chain in self.analyzer.primitive_chains],
            "primitive_chain_graph_dot": self.chain_graph_dot(),
            "attack_surface": self.attack_surface_rows(),
            "correlations": self.analyzer.correlations,
            "findings": [finding.__dict__ for finding in self.analyzer.findings],
            "functions": complete_functions,
            "pseudocode": [
                {
                    "ea": ea,
                    "ea_text": ea_text(ea),
                    "function": (self._function_summary_for_ea(ea).name if self._function_summary_for_ea(ea) else safe_name(ea)),
                    "text": text
                }
                for ea, text in sorted(self.analyzer.pseudocode_by_ea.items())
            ],
            "pseudocode_failures": self.analyzer.pseudocode_failures,
            "generated_c_structs": self._generated_c_structs_for_report(),
            "critical_strings": [{"ea": ea, "ea_text": ea_text(ea), "text": text} for ea, text in self.analyzer.critical_strings],
            "device_path_guesses": self._device_path_guesses(),
            "ioctl_candidates": self._ioctl_candidates(),
            "dynamic_proof_plan": self.dynamic_plan_text(),
            "deep_pseudocode_report": self.pseudocode_deep_report(),
            "msrc_intigriti_proof_pack": self.proof_pack_text_report(),
            "msrc_intigriti_proof_pack_manifest": self._proof_pack_manifest(),
            "dynamic_evidence_manifest": self._dynamic_manifest(),
            "controlled_fuzz_plan": self.fuzz_plan_text(),
            "controlled_fuzz_manifest": self._fuzz_manifest(),
            "clipboard_ready_tsv": {
                "findings": self._table_to_tsv(self.findings_table, False),
                "functions": self._table_to_tsv(self.funcs_table, False),
                "attack_surface": self._table_to_tsv(self.attack_surface_table, False),
                "primitive_chains": self._table_to_tsv(self.chains_table, False),
                "correlations": self._table_to_tsv(self.correlation_table, False)
            },
            "tab_text": {
                "dashboard": self.dashboard.toPlainText(),
                "attack_surface": self._table_to_tsv(self.attack_surface_table, False),
                "pseudocode_current": self.pseudo_text.toPlainText(),
                "dynamic_proof_lab": self.dynamic_text.toPlainText(),
                "proof_pack": self.proof_pack_text.toPlainText(),
                "controlled_fuzz": self.fuzz_text.toPlainText(),
                "knowledge": self.knowledge_text.toPlainText(),
                "details": self.details.toPlainText()
            },
            "standard_markdown_report": self.analyzer.markdown_report(),
            "rules": self.rules,
            "safety_notes": [
                "Static findings are triage hypotheses until dynamic evidence confirms reachability and impact.",
                "chain_type=pseudocode is a plausible static path, not final proof.",
                "no-nearby-guard-in-pseudocode-window means no nearby guard token in decompiled text, not proof of absent validation.",
                "Scores and confidence values are review priorities, not bounty confirmations.",
                "The exported PowerShell probe is non-destructive and does not call DeviceIoControl.",
                "The exported C++ harness requires explicit opt-in flags before DeviceIoControl.",
                "Active IOCTL tests must be case-specific, reversible, and authorized."
            ]
        }

    def _complete_text_report(self, report: dict[str, Any]) -> str:
        target = report.get("target", {})
        lines = [
            "Dragon Reverse Complete Evidence Report",
            "Generated UTC: %s" % report.get("generated_utc", ""),
            "",
            "Target",
            "  File: %s" % target.get("file", ""),
            "  Path: %s" % target.get("path", ""),
            "  SHA256: %s" % target.get("sha256", ""),
            "  Hex-Rays: %s" % ("available" if report.get("summary", {}).get("hexrays_available") else "not available/not run"),
            "",
            "Summary",
        ]
        for key, value in report.get("summary", {}).items():
            lines.append("  %s: %s" % (key, value))
        lines += [
            "",
            "Standard Markdown Report",
            report.get("standard_markdown_report", ""),
            "",
            "Findings TSV",
            report.get("clipboard_ready_tsv", {}).get("findings", ""),
            "",
            "Functions TSV",
            report.get("clipboard_ready_tsv", {}).get("functions", ""),
            "",
            "Attack Surface TSV",
            report.get("clipboard_ready_tsv", {}).get("attack_surface", ""),
            "",
            "Primitive Chains TSV",
            report.get("clipboard_ready_tsv", {}).get("primitive_chains", ""),
            "",
            "Primitive Chain Graph DOT",
            report.get("primitive_chain_graph_dot", ""),
            "",
            "Correlations TSV",
            report.get("clipboard_ready_tsv", {}).get("correlations", ""),
            "",
            "Dynamic Proof Plan",
            report.get("dynamic_proof_plan", ""),
            "",
            "MSRC/Intigriti Proof Pack",
            report.get("msrc_intigriti_proof_pack", ""),
            "",
            "Deep Pseudocode Report",
            report.get("deep_pseudocode_report", ""),
            "",
            "Generated C Struct Candidates",
            "\n\n".join(item.get("c_struct", "") for item in report.get("generated_c_structs", [])),
            "",
            "Controlled Fuzz Plan",
            report.get("controlled_fuzz_plan", ""),
            "",
            "Current Pseudocode Tab",
            report.get("tab_text", {}).get("pseudocode_current", ""),
            "",
            "Knowledge Tab",
            report.get("tab_text", {}).get("knowledge", ""),
            "",
            "Full Structured Evidence JSON",
            json.dumps(report, indent=2)
        ]
        return "\n".join(lines) + "\n"

    def _severity_brush(self, severity: str) -> QtGui.QBrush:
        colors = {
            "Critical": "#b00020",
            "High": "#c45100",
            "Medium": "#9a6a00",
            "Low": "#1f6feb",
            "Info": "#5f6b7a"
        }
        return QtGui.QBrush(QtGui.QColor(colors.get(severity, "#444444")))

    def _severity_badge_html(self, severity: str, count: int) -> str:
        colors = self._severity_colors(severity)
        return (
            "<span style='display:inline-block; min-width:92px; padding:3px 8px; "
            "border-radius:5px; color:%s; background:%s; font-weight:600;'>%s: %d</span>"
        ) % (colors["fg"], colors["bg"], self._html(severity), count)

    def _html(self, text: Any) -> str:
        return str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


class DragonReverseForm(ida_kernwin.PluginForm):
    def OnCreate(self, form: Any) -> None:
        self.parent = self.FormToPyQtWidget(form)
        self.widget = DragonReverseWidget(self.parent)
        layout = QtWidgets.QVBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(self.widget)
        self.parent.setLayout(layout)

    def OnClose(self, form: Any) -> None:
        global _form
        _form = None


_form: DragonReverseForm | None = None
_registered = False


def show_dragon_reverse() -> None:
    global _form
    try:
        ida_kernwin.msg("[DragonReverse] opening panel...\n")
        if _form is None:
            _form = DragonReverseForm()
        options = 0
        for name in ("WOPN_TAB", "WOPN_MENU", "WOPN_RESTORE"):
            options |= int(getattr(ida_kernwin.PluginForm, name, 0))
        try:
            _form.Show(PLUGIN_TITLE, options=options)
        except TypeError:
            _form.Show(PLUGIN_TITLE)
    except Exception:
        ida_kernwin.msg("[DragonReverse] failed to open panel\n%s\n" % traceback.format_exc())
        try:
            ida_kernwin.warning("Dragon Reverse failed to open. Check the Output window for the traceback.")
        except Exception:
            pass


class OpenDragonReverseAction(ida_kernwin.action_handler_t):
    def activate(self, ctx: Any) -> int:
        show_dragon_reverse()
        return 1

    def update(self, ctx: Any) -> int:
        return ida_kernwin.AST_ENABLE_ALWAYS


def register_action() -> None:
    global _registered
    if _registered:
        return
    desc = ida_kernwin.action_desc_t(
        ACTION_OPEN,
        PLUGIN_TITLE,
        OpenDragonReverseAction(),
        "",
        "Open Dragon Reverse driver triage panel",
        -1
    )
    try:
        ida_kernwin.register_action(desc)
    except Exception:
        pass
    try:
        ida_kernwin.attach_action_to_menu("View/Open subviews/", ACTION_OPEN, ida_kernwin.SETMENU_APP)
    except Exception:
        try:
            ida_kernwin.attach_action_to_menu("View/", ACTION_OPEN, ida_kernwin.SETMENU_APP)
        except Exception:
            pass
    _registered = True


class DragonReversePlugin(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_KEEP
    comment = "Dragon Reverse Windows driver triage and correlation"
    help = "Open Edit > Plugins > Dragon Reverse or View > Open subviews > Dragon Reverse"
    wanted_name = PLUGIN_TITLE
    wanted_hotkey = "Ctrl-Shift-D"

    def init(self) -> int:
        register_action()
        ida_kernwin.msg("[DragonReverse] loaded. Use Ctrl+Shift+D, Edit > Plugins > Dragon Reverse, or View > Open subviews > Dragon Reverse.\n")
        return ida_idaapi.PLUGIN_KEEP

    def run(self, arg: int) -> None:
        show_dragon_reverse()

    def term(self) -> None:
        pass


def PLUGIN_ENTRY() -> DragonReversePlugin:
    return DragonReversePlugin()
