<p align="center">
  <img src="https://img.shields.io/badge/Version-2.0-red?style=for-the-badge" alt="Version">
  <img src="https://img.shields.io/badge/Language-C++17-blue?style=for-the-badge" alt="Language">
  <img src="https://img.shields.io/badge/Platform-Windows-green?style=for-the-badge" alt="Platform">
  <img src="https://img.shields.io/badge/Build-MSVC-purple?style=for-the-badge" alt="Build">
</p>

# PEDefeat v2.0 — Universal Detection Surface Analyzer & Defeat Engine

**Author:** Khaled M. Alshammri | [@ik0z](https://github.com/ik0z)

> All-in-one detection surface analyzer for PE binaries and scripts. Pinpoints exactly what AV/EDR flags — with severity, explanation, and fix. Zero configuration required.

---

## Features

### Multi-Format Analysis
PEDefeat v2.0 is not limited to PE files. It analyzes **any executable or script type** and produces detailed reports showing every detection surface point.

| Type | Extensions |
|------|-----------|
| **PE Binaries** | `.exe`, `.dll`, `.sys` |
| **PowerShell** | `.ps1`, `.psm1`, `.psd1` |
| **Batch** | `.bat`, `.cmd` |
| **VBScript** | `.vbs`, `.vbe` |
| **JScript** | `.js`, `.jse` |
| **HTA / WSF** | `.hta`, `.wsf` |
| **.NET** | Auto-detected via CLR metadata |

### Deep Static Analysis (PE)
- **Header Analysis** — ASLR, DEP, CFG, SEH, timestamps, checksums, entry point location, Rich header
- **Section Analysis** — Entropy calculation (packer/crypto detection), RWX permissions, non-standard section names, virtual>>raw size ratios
- **Import Table (IAT)** — 65+ suspicious API patterns across 12+ categories (process injection, memory manipulation, credential theft, token abuse, evasion, shellcode, etc.)
- **Export Table (EAT)** — Reflective loader exports, DLL name masquerading
- **TLS Callbacks** — Pre-entry-point execution detection
- **String Extraction** — 55+ suspicious string patterns: AMSI/ETW references, C2 channels, tool names, shell commands, crypto APIs, ransomware indicators, LOLBins, UAC bypass, persistence mechanisms
- **Version Info** — Fake identity detection, filename mismatches, missing manifests

### Script Analysis Engine
- **50+ detection patterns** for PowerShell, Batch, VBScript, JScript, and HTA
- **AMSI bypass detection** — `AmsiScanBuffer`, `AmsiInitFailed`, patching patterns
- **ETW bypass detection** — `EtwEventWrite`, tracing manipulation
- **Execution patterns** — `IEX`, `Invoke-Expression`, encoded commands, `DownloadString`
- **Shellcode detection** — P/Invoke, `DllImport`, `VirtualAlloc`, byte array patterns
- **Credential access** — SAM/LSASS/Mimikatz/token patterns
- **Persistence** — Registry, scheduled tasks, WMI subscriptions, startup folders
- **Lateral movement** — WinRM, PSRemoting, WMI execution
- **Heuristics** — Entropy analysis, base64 blob detection, obfuscation (long lines), encoded payloads

### AMSI Trigger Finder
Inspired by [AMSITrigger](https://github.com/RythmStick/AMSITrigger) and [DefenderCheck](https://github.com/matterpreter/DefenderCheck):
- Loads `amsi.dll` natively via `LoadLibrary` / `GetProcAddress`
- Initializes AMSI context mimicking PowerShell's exact initialization string
- Verifies AMSI is active (real-time protection check)
- **Chunk-based scanning** (4096 byte chunks) with binary search for exact trigger boundaries
- Reports exact **byte offset**, **hex context**, and **ASCII representation** of each trigger region
- Finds up to 20 trigger regions per file

### Defender Signature Split Scan
- Automatically locates `MpCmdRun.exe` (Defender's command-line scanner)
- Splits the target binary in half and scans each half
- Identifies which portion of the file contains Defender signature matches
- Reports detections with offset ranges

### Dynamic Analysis
- Creates target process in **suspended state** (never actually executes)
- Inspects **PEB** (Process Environment Block) for anomalies
- Runs **PE-sieve** on the live suspended process for memory scanning
- Safely terminates the process after analysis

### External Tool Integration (Zero Configuration)
All tools are **auto-detected** — no manual paths required:
- **YARA** — Full rule scanning with auto-discovered rules
- **Sigma** — Detection rule matching against PE properties
- **Sysinternals** — `sigcheck` (digital signature), `strings` (deep extraction)
- **PE-sieve** — Live process memory scanning for hooks, hollowing, injection

### Report Generation
Three output formats, all containing full findings with severity, category, explanation, code context, and fix recommendations:

| Format | Description |
|--------|-------------|
| **TXT** | Structured text report with all findings |
| **HTML** | Dark-themed dashboard with severity badges, section tables, color-coded findings |
| **JSON** | Machine-readable format for integration with CI/CD, SIEM, or custom tools |

### Plugin System
Extensible via DLL plugins. Any DLL in the `plugins/` directory exporting `PluginAnalyze` is automatically loaded and executed.

---

## Quick Start

```bash
build.bat
bin\PEDefeat.exe target.exe --all --deep
```

## Usage

```
PEDefeat.exe <target> [options]

Options:
  --output=<dir>       Report output dir (default: .\reports)
  --html               HTML report (dark-themed dashboard)
  --txt                TXT report (default)
  --json               JSON report (machine-readable)
  --all                All report formats (TXT + HTML + JSON)
  --amsi               AMSI-based trigger finder
  --defender           Defender signature split scan
  --dynamic            Dynamic analysis (suspended process + PEB + PE-sieve)
  --deep               Enable ALL analysis modes (amsi + defender + dynamic)
  --yara=<dir>         YARA rules dir (auto-detected if not specified)
  --sigma=<dir>        Sigma rules dir (auto-detected if not specified)
  --pesieve=<path>     pe-sieve path (auto-detected if not specified)
  --sysinternals=<dir> Sysinternals dir (auto-detected if not specified)
  --plugins=<dir>      Plugin DLLs dir (auto-detected if not specified)
  --severity=<level>   Min severity: critical | high | medium | low | info
  --verbose            Detailed output + show auto-detected tool paths
  --no-color           Disable ANSI colors
  --quick              Skip external tools (static analysis only)
```

### Examples

```bash
# Full deep analysis — all reports, AMSI, Defender, dynamic
bin\PEDefeat.exe payload.exe --all --deep

# Analyze PowerShell script
bin\PEDefeat.exe bypass.ps1 --html --verbose

# AMSI trigger scan only
bin\PEDefeat.exe implant.dll --amsi --all

# Defender split scan, high severity only
bin\PEDefeat.exe agent.exe --defender --severity=high --all

# Analyze batch file
bin\PEDefeat.exe loader.bat --all

# Quick static-only, no colors (CI/CD friendly)
bin\PEDefeat.exe target.sys --quick --no-color --json

# Full verbose analysis
bin\PEDefeat.exe c2_client.exe --deep --verbose --all
```

---

## Zero Configuration — Auto-Detection

PEDefeat v2.0 automatically searches for external tools in this order:

1. `tools/` directory relative to `PEDefeat.exe`
2. `tools/` directory relative to the target file
3. Parent directory (e.g., `Scanners/`)
4. System `PATH`

| Directory | What It Finds |
|-----------|--------------|
| `tools/sysinternals/` | `sigcheck.exe`, `strings.exe` |
| `tools/pe-sieve/` | `pe-sieve64.exe` / `pe-sieve32.exe` |
| `tools/yara/` | `yara64.exe` / `yara32.exe` |
| `rules/yara/` | `.yar` / `.yara` rule files |
| `rules/sigma/` | `.yml` / `.yaml` / `.sigma` rule files |
| `plugins/` | Plugin DLLs |

---

## Project Structure

```
PEDefeat/
├── bin/
│   └── PEDefeat.exe           # Built executable
├── tools/
│   ├── sysinternals/           # Sysinternals Suite (auto-detected)
│   ├── pe-sieve/               # PE-sieve (auto-detected)
│   └── yara/                   # YARA (auto-detected)
├── rules/
│   ├── yara/                   # YARA rules (auto-scanned)
│   └── sigma/                  # Sigma rules (auto-scanned)
├── plugins/                    # Plugin DLLs (auto-loaded)
├── reports/                    # Generated reports (TXT, HTML, JSON)
├── PEDefeat_v2.cpp             # v2.0 source (single-file C++17)
├── PEDefeat.cpp                # Legacy v1.0 source
├── build.bat                   # MSVC build script
├── requirements.txt            # External tools & rules setup guide
└── README.md
```

---

## Plugin Development

Create a DLL with the following exported function:

```c
extern "C" __declspec(dllexport) void PluginAnalyze(
    const char* filePath,
    const unsigned char* fileData,
    unsigned int fileSize,
    void* context
);

// Optional: provide a display name
extern "C" __declspec(dllexport) const char* PluginName() {
    return "MyCustomPlugin";
}
```

Place the DLL in the `plugins/` directory — it will be automatically loaded and executed during analysis.

---

## Credits & Acknowledgments

PEDefeat v2.0 was built with inspiration and concepts from the following open-source projects and tools:

| Project | Author | Contribution |
|---------|--------|-------------|
| [DefenderCheck](https://github.com/matterpreter/DefenderCheck) | [@maboroshi](https://github.com/matterpreter) | Concept of binary splitting to identify Defender signature bytes |
| [AMSITrigger](https://github.com/RythmStick/AMSITrigger) | [@_RythmStick](https://github.com/RythmStick) | AMSI chunk scanning and trigger localization algorithm |
| [PE-sieve](https://github.com/hasherezade/pe-sieve) | [@hasherezade](https://github.com/hasherezade) | Runtime process memory scanning for hooks and hollowing |
| [YARA](https://github.com/VirusTotal/yara) | VirusTotal | Pattern matching engine and rule format |
| [Sigma](https://github.com/SigmaHQ/sigma) | SigmaHQ | Generic signature format for detection rules |
| [Sysinternals Suite](https://learn.microsoft.com/en-us/sysinternals/) | Mark Russinovich (Microsoft) | `sigcheck` for digital signature verification, `strings` for deep string extraction |
| [signature-base](https://github.com/Neo23x0/signature-base) | Florian Roth ([@Neo23x0](https://github.com/Neo23x0)) | Community YARA rules for malware and threat detection |

---

## Disclaimer

> **This tool is designed and intended for educational and security research purposes only.**
>
> PEDefeat v2.0 is a detection surface analysis tool created to help security researchers, malware analysts, and students understand how antivirus engines and endpoint detection systems identify malicious patterns in binaries and scripts.
>
> **Intended use cases:**
> - Academic research in malware analysis and reverse engineering
> - Understanding AV/EDR detection mechanisms
> - Security testing in authorized environments
> - Digital forensics and incident response training
>
> **The author assumes no responsibility for any misuse of this tool.** Users are solely responsible for ensuring their use complies with all applicable local, national, and international laws and regulations. Unauthorized use of this tool against systems you do not own or have explicit permission to test is strictly prohibited and may violate computer crime laws.
>
> By using this tool, you agree that you will only use it in authorized, legal, and ethical contexts.

---

## License

This project is provided for **educational and research purposes only**. All rights reserved.

Copyright (c) 2024-2026 Khaled M. Alshammri ([@ik0z](https://github.com/ik0z))
