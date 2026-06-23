# Dragon Reverse

Dragon Reverse is an IDA Pro 9.2+ plugin for authorized Windows driver
vulnerability research. It builds a review queue from static signals and known
BYOVD-style driver families, then correlates those signals against unknown
drivers.

## What it does

- Finds risky imports, strings, instructions, and IOCTL constants.
- Decodes suspicious IOCTL constants, including `FILE_ANY_ACCESS` and
  `METHOD_NEITHER`.
- Correlates functions with known families: physical memory mapping, MSR
  programming, raw port/register IO, privileged registry writes, weak device
  exposure, user-pointer trust, kernel memory primitives, DMA/MDL paths,
  firmware variables, ALPC/WMI boundaries, object namespace confusion,
  impersonation, executable mappings, and IRP lifetime/race patterns.
- Infers function roles such as `IOCTL dispatcher`, `Physical memory mapper`,
  `MSR control path`, `Registry/service-key writer`, and `Process/token object
  path`.
- Adds a Hex-Rays pseudocode profile above decompiled functions with roles,
  IOCTLs, signals, and a review checklist.
- Adds `Deep pseudocode scan`, which extracts structured pseudo-code facts:
  user buffers, length fields, dispatch assignments, sensitive sinks, guards,
  suppressions, and proof notes.
- Improves V3 pseudocode proofing with alias-based data-flow lite,
  `CTL_CODE(...)` / bit-expression IOCTL recovery, IOCTL structure field
  suggestions from buffer offsets, and ordinal import visibility.
- Adds `Generate C struct` buttons in the Pseudocode and Proof Pack tabs. They
  turn recovered IOCTL buffer offsets into packed C structs suitable as a
  harness/report starting point.
- Adds V4 structure hardening: conflicting recovered uses of the same IOCTL
  buffer offset are emitted as C `union` candidates, which helps review
  sub-command layouts and per-IOCTL buffer reuse.
- Tracks `ProbeForRead` / `ProbeForWrite` size arguments against the recovered
  structure footprint. Under-sized or unresolved fixed-small probes are promoted
  as high-priority review hypotheses for overflow/OOB validation.
- Adds V5 analysis modes: `Auto`, `Driver`, `Service`, `Hypervisor`, and
  `Universal`. Modes filter the rule families used for scoring instead of only
  changing labels.
- Adds an `Attack Surface` tab that groups entry points by domain: IOCTL/device
  objects, RPC interfaces, named pipes, COM/DCOM classes, ALPC/named ports,
  impersonation boundaries, privileged file/symlink operations, hypercalls, and
  VMBus/virtual-device parsers.
- Adds service and hypervisor pseudocode facts: UUID/CLSID literals,
  RPC/COM/pipe/ALPC surfaces, VMBus/hypercall signals, privileged file sinks,
  impersonation sinks, and TOCTOU-lite user-buffer reread candidates.
- Adds a dedicated caller-mode gate heuristic: user/IOCTL-facing sensitive
  sinks without visible `PreviousMode`, `RequestorMode`, or `ExGetPreviousMode`
  are promoted as high-priority review hypotheses.
- Adds syntax highlighting in pseudocode/proof text views: sources, sinks,
  guards/caller-mode checks, IOCTL constants, and missing-gate warnings use
  distinct colors.
- Adds V3 review features: `chain_type` (`strict`, `pseudocode`,
  `profile_seed`), confidence reasons, manual review statuses (`verified`,
  `needs proof`, `false positive`), a chain graph tab with DOT export, and a
  controlled fuzz planning tab that never executes IOCTLs from IDA.
- Adds a `Proof pack` tab for MSRC/Intigriti-style evidence ordering: driver
  identity, low-privileged device access, dispatch assignment, IOCTL
  access/methods, and per-IOCTL static links to memory/MDL/port sinks.
- Adds `Export VS project` from the Proof Pack tab. It writes a Visual Studio
  2022 x64 solution with the controlled harness, inferred struct header,
  proof manifest, and report-ready worksheet.
- Adds `Full Scan`, which runs static triage, all-function Hex-Rays pseudocode
  scanning, role inference, call graph enrichment, and IOCTL reachability
  propagation.
- Adds `Primitive chains`, a stricter view that ranks likely chains such as
  exposed IOCTL surface -> physical memory mapping, MDL/DMA, port I/O,
  registry/service-key, token/process, firmware/PCI, WMI/ALPC, or executable
  mapping primitives.
- Adds copy buttons in every tab for fast TSV/text extraction into Intigriti or
  MSRC reports.
- Adds `Export full report`, a single evidence export that writes JSON by
  default or TXT when the filename ends in `.txt`, including the Proof Pack.
- Provides a Dynamic Proof Lab with a non-destructive proof plan, PowerShell
  probe export, controlled C++ harness export, and evidence manifest export.
- Checks the loaded binary against local known hashes from `Driver vulnerable`
  and `Driver suspect`.
- Checks filename-only BYOVD profile seeds for well-known driver families,
  including expected primitives, CVE references, and public tooling references.
  Filename-only matches are triage hints and must be confirmed by hash/version.
- Optionally fetches `https://www.loldrivers.io/api/drivers.json` inside IDA
  and matches the loaded driver by SHA-256.
- Exports JSON and Markdown reports.

## Files

- `ida_plugin/dragon_reverse.py`: IDA plugin.
- `ida_plugin/dragon_reverse_logic.py`: pure scoring/correlation helpers used
  by the plugin and unit tests.
- `ida_plugin/dragon_reverse_rules.json`: knowledge base and local profiles.
- `tools/dragon_reverse_corpus_scan.py`: offline scanner for local driver folders.
- `reports/dragon_reverse_corpus_audit.md`: generated local corpus report.
- `reports/dragon_reverse_corpus_audit.json`: generated local corpus data.

## Install

Copy these three files into `C:\Program Files\IDA Professional 9.2\plugins`:

- `ida_plugin/dragon_reverse.py`
- `ida_plugin/dragon_reverse_logic.py`
- `ida_plugin/dragon_reverse_rules.json`

Restart IDA, then use `Ctrl+Shift+D`, `Edit > Plugins > Dragon Reverse`, or
`View > Open subviews > Dragon Reverse`.

## Use

1. Open a driver, service executable, DLL, or virtualization component in IDA
   and wait for auto-analysis.
2. Open Dragon Reverse.
3. Select a mode: `Driver` for `.sys`, `Service` for SYSTEM services/RPC/COM,
   `Hypervisor` for Hyper-V/VMware/VirtualBox-style components, or `Auto` /
   `Universal` when unsure.
4. Run `Run static analysis`.
5. Use `Run + pseudocode` when Hex-Rays is available and you want role
   inference from decompiled functions.
6. Use `Full Scan` when you want the deepest pass: every function is scanned
   where Hex-Rays can decompile it, pseudo-code is retained in the complete
   report, and IOCTL-reachable callees are marked.
7. Start manual review from `Attack Surface`, then pivot into `Primitive
   chains`, `Zero-day correlator`, `Findings`, and `Functions`.
8. Use `Dynamic proof lab` to export the non-destructive PowerShell probe,
   controlled C++ harness, or JSON evidence manifest.
9. Use `Proof pack` to select one focus IOCTL and generate a report-ready
   worksheet for MSRC/Intigriti. The pack documents what is static-ready and
   what still needs low-privileged dynamic proof.
10. Use `Export VS project` when you want a ready-to-build proof workspace with
   `dragon_reverse_harness.cpp`, `dragon_reverse_structs.h`, `.sln/.vcxproj`,
   `proof_manifest.json`, and `proof_pack.txt`.
11. Use `Controlled fuzz` to export a safe fuzz plan/manifest for VM-only,
   opt-in testing. The plugin does not execute fuzzing or `DeviceIoControl`.
12. Use `Export full report` for a complete evidence bundle containing target
   metadata, findings, functions, inferred roles, IOCTLs, correlations,
   clipboard-ready TSV tables, dynamic proof plan, Proof Pack, manifest,
   current pseudocode tab text, all pseudocode collected by `Full Scan`, and
   the loaded rules.

`Export full report` automatically runs `Full Scan` first if the current IDB has
not already been fully scanned.

V5 service/hypervisor findings follow the same rule as driver findings: they are
triage hypotheses until dynamic reachability, authorization context, and a
specific reversible proof are documented. TOCTOU-lite means “same user-controlled
source appears checked and later reread,” not automatic exploitability.

Scores are triage hints, not vulnerability claims. A `chain_type=pseudocode`
chain is a plausible static path, not final proof. A
`no-nearby-guard-in-pseudocode-window` note means no nearby guard token was
observed in decompiled text; it does not prove validation is absent.
`union_candidate=yes` means the same offset had multiple inferred uses and must
be verified against the exact IOCTL branch. `probe_size_mismatch` means the
recovered structure footprint and visible `ProbeForRead`/`ProbeForWrite` size
argument do not reconcile cleanly; it is a high-priority review hypothesis, not
standalone proof.
`review_priority` in the offline corpus report is the field used for ordering:
it favors the local vulnerable/suspect corpus and penalizes noisy core Windows
drivers, missing user surfaces, and mitigation signals.

The PowerShell probe does not call `DeviceIoControl`. The C++ harness keeps
active IOCTL testing disabled unless both `--allow-deviceiocontrol` and
`--i-understand-this-can-crash` are provided with an explicitly selected IOCTL.
When active testing is explicitly enabled, the harness can emit JSONL proof
artifacts with `--jsonl`, `--case-id`, `--in-size`, `--out-size`, `--repeat`,
and `--sleep-ms`. It records return status, `GetLastError`, input/output sizes,
bytes returned, and a short output preview for reproducible bounty evidence.

## Audit hardening

- Full Scan keeps IDA/Hex-Rays calls on the main thread and pumps Qt events
  between decompilations. A QThread is intentionally avoided because IDA and
  Hex-Rays APIs are not safe to call from arbitrary worker threads.
- Hex-Rays pseudocode is cached per function during the analyzer lifetime, so a
  Full Scan and later manual pseudocode views do not re-decompile the same
  function unnecessarily.
- The UI blocks re-entrant analysis/export actions while an analysis is running,
  which protects `self.analyzer` from being replaced mid-scan.
- Pure helper tests live under `tests/` and cover strict IOCTL decoding,
  severity thresholds, and signal matching rules that reduce false positives.
- Pseudocode scoring suppresses common noise such as `memmove` without visible
  user buffer/length context, and `ZwOpenKey` without a write sink.
- Cross-family correlations boost high-value combinations such as weak device
  exposure plus memory primitives, IOCTL/user-pointer surface plus sensitive
  sinks, hardware-control bundles, and process-control/protection-bypass paths.

Run the quick checks with:

```powershell
python -m unittest discover -s tests
python -m py_compile ida_plugin\dragon_reverse.py ida_plugin\dragon_reverse_logic.py tools\dragon_reverse_corpus_scan.py tools\dragon_reverse_shared.py
```



⚠️ Disclaimer
This tool is developed for authorized security research, bug bounty hunting, and educational purposes only. The author (Leksa667) is not responsible for any illegal use or damage caused by this software. Use it at your own risk within legal and authorized boundaries.
