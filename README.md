# 🕵️ Threat Hunt: Suspected Data Exfiltration from a PIP'd Employee

> **Platform:** Microsoft Defender for Endpoint (MDE) + Azure CyberRange  
> **Analyst:** Saran  
> **Hunt Date:** March 28, 2026  
> **Severity:** 🔴 High — Confirmed Exfiltration  
> **Status:** ✅ Confirmed & Escalated to Management

---

## 📋 Table of Contents

- [Overview](#overview)
- [Scenario Background](#scenario-background)
- [Hunt Methodology](#hunt-methodology)
- [Key Findings](#key-findings)
- [MITRE ATT&CK Mapping](#mitre-attck-mapping)
- [Response Actions Taken](#response-actions-taken)
- [Lessons Learned](#lessons-learned)
- [KQL Query Reference](#kql-query-reference)
- [Project Structure](#project-structure)
- [Tools & Technologies](#tools--technologies)

---

## Overview

This repository documents a **threat hunting exercise** simulating an insider threat investigation conducted in a live Azure CyberRange environment using **Microsoft Defender for Endpoint (MDE)** and **Kusto Query Language (KQL)**. The investigation was triggered after management raised concerns that a recently PIP'd employee may be planning to steal proprietary company data before resigning.

The investigation confirmed that the employee's device (`saranpc2`) was used to **silently install 7-Zip**, **archive sensitive employee data**, and **exfiltrate it to an external Azure Blob Storage endpoint** via an encrypted HTTPS connection — all orchestrated through a PowerShell script executed with `-ExecutionPolicy Bypass`.

**Bottom Line Up Front (BLUF):** Data exfiltration was confirmed. A PowerShell script (`exfiltratedata.ps1`) automated the full kill chain — from archiving sensitive files using 7-Zip to uploading them to `sacyberrange00.blob.core.windows.net` over port 443. Findings were escalated to the employee's manager. No evidence of USB-based exfiltration was found.

---

## Scenario Background

An employee — **John Doe** — working in a sensitive department was recently placed on a **Performance Improvement Plan (PIP)**. Following a confrontation with management, concerns were raised that John may attempt to steal proprietary information before leaving the company.

Key risk factors identified at the start of the investigation:

- John has **local administrator rights** on his corporate device (`saranpc2`)
- **No application restrictions** — any software can be installed
- John has legitimate access to sensitive company data as part of his role
- Potential methods: archiving/compressing files and sending to a personal or cloud drive

**Hypothesis:**
> *"John may be using his administrator privileges to silently install archiving tools, compress sensitive company data, and transfer it to an external destination — potentially a personal cloud storage account."*

---

## Hunt Methodology

This investigation follows the structured **Threat Hunting Lifecycle**:

```
1. Preparation  →  2. Data Collection  →  3. Data Analysis
       ↑                                         ↓
7. Improvement  ←  6. Documentation  ←  4. Investigation
                                         ↓
                                    5. Response
```

For the full step-by-step walkthrough, see [`reports/hunt-report.md`](reports/hunt-report.md).

---

## Key Findings

| Finding | Detail |
|---|---|
| **Affected Device** | `saranpc2` (John Doe's corporate device) |
| **Archive Tool Used** | `7z.exe` — silently installed via PowerShell |
| **Files Archived** | `employee-data.csv` and other sensitive files |
| **Archive Format** | `.zip` / `.7z` |
| **Exfiltration Script** | `exfiltratedata.ps1` — stored at `C:\programdata\` |
| **Exfiltration Destination** | `sacyberrange00.blob.core.windows.net` (Azure Blob Storage) |
| **Destination IP** | `20.60.181.193` |
| **Protocol** | HTTPS — port 443 (encrypted, blends with normal traffic) |
| **USB Exfiltration** | ❌ No evidence found |
| **Escalated To** | Employee's manager — full evidence package provided |

---

## MITRE ATT&CK Mapping

| TTP ID | Technique | Tactic | Observed |
|---|---|---|---|
| [T1560.001](https://attack.mitre.org/techniques/T1560/001/) | Archive Collected Data: Archive via Utility | Collection | 7z.exe used to compress sensitive files |
| [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | PowerShell | Execution | `exfiltratedata.ps1` run with `-ExecutionPolicy Bypass` |
| [T1071.001](https://attack.mitre.org/techniques/T1071/001/) | Application Layer Protocol: Web Protocols | Exfiltration | HTTPS to Azure Blob Storage on port 443 |
| [T1048](https://attack.mitre.org/techniques/T1048/) | Exfiltration Over Alternative Protocol | Exfiltration | Cloud storage used as exfiltration channel |
| [T1027](https://attack.mitre.org/techniques/T1027/) | Obfuscated Files or Information | Defense Evasion | Data compressed before transfer |
| [T1070.004](https://attack.mitre.org/techniques/T1070/004/) | Indicator Removal: File Deletion | Defense Evasion | Potential post-exfiltration cleanup (inferred) |

See [`mitre/ttp-mapping.md`](mitre/ttp-mapping.md) for detailed analysis.

---

## Response Actions Taken

1. **Findings escalated to management** — full evidence package (archive activity, network connections, script content) presented to John's manager.
2. **USB exfiltration ruled out** — checked `DeviceFileEvents` for activity on removable drives (E–J drive letters) — no results.
3. **Evidence preserved** — all relevant logs from `DeviceFileEvents`, `DeviceProcessEvents`, and `DeviceNetworkEvents` retained for HR/legal proceedings.

---

## Lessons Learned

- 🔴 **Unrestricted admin rights** for end users is a significant insider threat enabler — John could silently install 7-Zip with no alerts.
- 🔴 **HTTPS exfiltration to cloud storage is almost invisible** without DLP — encrypted traffic to Azure Blob blends perfectly with legitimate activity.
- 🟡 **Timestamped pivoting across tables** (FileEvents → ProcessEvents → NetworkEvents) is the most effective technique for tracing the full kill chain.
- 🟢 **Archive file monitoring** (`DeviceFileEvents` for `.zip`/`.7z`) is a reliable early indicator of staging for exfiltration.
- 🟢 **Checking for USB exfiltration** via drive letter regex is a quick and valuable addition to any insider threat investigation.

---

## KQL Query Reference

All KQL queries used in this hunt are documented in [`queries/kql-queries.md`](queries/kql-queries.md), including:

- Detecting archive file creation (`.zip`, `.7z`)
- Timestamped pivot to process events around archive creation
- Identifying outbound network connections from suspicious scripts
- Checking for USB/removable drive exfiltration
- Detection engineering rules for future insider threat monitoring

---

## Project Structure

```
📁 soc-data-exfiltration/
├── 📄 README.md                        ← You are here
├── 📁 reports/
│   └── 📄 hunt-report.md               ← Full investigation report
├── 📁 queries/
│   └── 📄 kql-queries.md               ← All KQL queries with explanations
├── 📁 mitre/
│   └── 📄 ttp-mapping.md               ← MITRE ATT&CK framework mapping
├── 📁 playbooks/
│   └── 📄 insider-threat-response.md   ← IR playbook for insider threat scenarios
└── 📁 assets/
    ├── 📄 timeline.md                  ← Attack timeline reconstruction
    └── 📁 screenshots/                 ← Evidence screenshots from MDE
        ├── 01-zip-file-events.png
        ├── 02-process-events-7zip.png
        ├── 03-network-exfiltration.png
        └── 04-exfiltrate-script-content.png
```

---

## Tools & Technologies

| Tool | Purpose |
|---|---|
| **Microsoft Defender for Endpoint (MDE)** | Endpoint telemetry and evidence collection |
| **Kusto Query Language (KQL)** | Log analysis across File, Process, and Network events |
| **Microsoft Sentinel / MDE Portal** | SIEM/XDR query interface |
| **MITRE ATT&CK Navigator** | TTP mapping and adversary behaviour analysis |
| **Azure CyberRange** | Lab environment for hands-on practice |
| **7-Zip (`7z.exe`)** | Tool used by subject to compress data |
| **Azure Blob Storage** | External exfiltration destination |

---

## About This Project

This project was completed as part of a **CyberRange insider threat investigation exercise** simulating a real-world SOC analyst scenario. It demonstrates:

- Insider threat hypothesis development and investigation
- Multi-table KQL pivoting (File → Process → Network events)
- Timestamp-anchored correlation across event tables
- MITRE ATT&CK framework application to a full exfiltration kill chain
- Evidence packaging for HR/legal escalation
- Professional SOC documentation and reporting

> 💡 *If you're a recruiter or fellow analyst reviewing this — all queries were executed against live MDE telemetry in a sandboxed Azure environment. Findings are real.*

---

*Last updated: March 27, 2026 | Author: Saran*
