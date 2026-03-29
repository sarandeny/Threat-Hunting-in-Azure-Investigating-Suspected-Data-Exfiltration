# 📊 KQL Query Reference — Data Exfiltration Threat Hunt

> All queries were executed in **Microsoft Defender for Endpoint (MDE)**  
> Platform: MDE Advanced Hunting / Microsoft Sentinel  
> Hunt Date: March 27, 2026

---

## Table of Contents

1. [Detect Archive File Creation](#1-detect-archive-file-creation)
2. [Timestamped Pivot to Process Events](#2-timestamped-pivot-to-process-events)
3. [Identify Outbound Network Connections](#3-identify-outbound-network-connections)
4. [Check for USB / Removable Drive Exfiltration](#4-check-for-usb--removable-drive-exfiltration)
5. [Full Kill Chain Correlation Query](#5-full-kill-chain-correlation-query)
6. [Bonus: Detection Engineering Queries](#6-bonus-detection-engineering-queries)

---

## 1. Detect Archive File Creation

**Purpose:** Identify any archive files (`.zip`, `.7z`, `.rar`) being created on the suspect device — a primary indicator of data staging for exfiltration.

```kql
DeviceFileEvents
| where DeviceName == "saranpc2"
| where FileName endswith ".zip"
```

**Extended version — cover multiple archive formats and add context:**

```kql
DeviceFileEvents
| where DeviceName == "saranpc2"
| where FileName endswith ".zip"
    or FileName endswith ".7z"
    or FileName endswith ".rar"
    or FileName endswith ".tar"
    or FileName endswith ".gz"
| project Timestamp, DeviceName, ActionType, FileName, FolderPath,
    InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

**Field Reference:**

| Field | Description |
|---|---|
| `ActionType` | `FileCreated`, `FileModified`, `FileRenamed` — all relevant |
| `FolderPath` | Where the archive was saved — unusual paths are red flags |
| `InitiatingProcessFileName` | What created the archive — `powershell.exe` is suspicious |
| `InitiatingProcessCommandLine` | The exact command — shows script names and parameters |

**What to look for:**
- Archives created by `powershell.exe` or `cmd.exe` rather than a backup agent
- Archives saved to unusual paths (`C:\programdata\`, `C:\temp\`, desktop)
- Archive names referencing sensitive data (e.g., `employee-data`, `payroll`, `confidential`)
- Multiple archives created in a short time window

**Result (this hunt):**
Multiple `.zip` files created by `powershell.exe` — several involving sensitive employee data files. Timestamps noted for pivoting.

---

## 2. Timestamped Pivot to Process Events

**Purpose:** Using a timestamp from a suspicious archive creation event, query `DeviceProcessEvents` in a narrow time window to identify the exact process/script responsible.

```kql
let VMName = "saranpc2";
let specificTime = datetime(YYYY-MM-DDTHH:MM:SSZ); // Replace with timestamp from Step 1

DeviceProcessEvents
| where Timestamp between ((specificTime - 1m) .. (specificTime + 1m))
| where DeviceName == VMName
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, ProcessCommandLine
```

**Why ±1 minute?**
Most automated scripts execute their steps within seconds of each other. A 1-minute window on either side of the archive creation event is usually enough to capture the responsible process without flooding results with unrelated activity.

**What to look for:**
- `powershell.exe` with suspicious flags: `-ExecutionPolicy Bypass`, `-EncodedCommand`, `-NoProfile`
- Script names referencing exfiltration: `exfiltrate`, `upload`, `send`, `transfer`
- Tool installation commands: `7z`, `winrar`, `curl`, `wget`
- `cmd.exe` launching PowerShell (common staging pattern)

**Result (this hunt):**
`exfiltratedata.ps1` found executing at the same time as the archive creation. Command line:
```
powershell.exe -ExecutionPolicy Bypass -File C:\programdata\exfiltratedata.ps1
```
Script installed `7z.exe` silently, then used it to compress `employee-data.csv` into an archive.

---

**Same query adapted for NetworkEvents — pivot to find the upload:**

```kql
let VMName = "saranpc2";
let specificTime = datetime(YYYY-MM-DDTHH:MM:SSZ); // Same timestamp

DeviceNetworkEvents
| where Timestamp between ((specificTime - 1m) .. (specificTime + 1m))
| where DeviceName == VMName
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, RemoteUrl, RemoteIP,
    RemotePort, InitiatingProcessFileName, InitiatingProcessCommandLine
```

**Result (this hunt):**
Outbound `ConnectionSuccess` to `sacyberrange00.blob.core.windows.net` (`20.60.181.193`) on port 443 — confirmed exfiltration upload.

---

## 3. Identify Outbound Network Connections

**Purpose:** Directly query for suspicious outbound connections from the device — particularly to cloud storage or file-sharing services.

```kql
DeviceNetworkEvents
| where DeviceName == "saranpc2"
| where ActionType == "ConnectionSuccess"
| where InitiatingProcessFileName =~ "powershell.exe"
| where RemotePort == 443
| project Timestamp, RemoteUrl, RemoteIP, RemotePort,
    InitiatingProcessCommandLine, ActionType
| order by Timestamp desc
```

**What to look for:**
- Connections from `powershell.exe` or `cmd.exe` to external IPs — especially unexpected
- Cloud storage domains: `blob.core.windows.net`, `drive.google.com`, `dropbox.com`, `mega.nz`
- File-sharing services: `wetransfer.com`, `gofile.io`, `transfer.sh`
- `ConnectionSuccess` — confirms data was actually transferred, not just attempted

**Suspicious domain indicators:**
```kql
// Expand to check for common exfiltration destinations
DeviceNetworkEvents
| where DeviceName == "saranpc2"
| where ActionType == "ConnectionSuccess"
| where RemoteUrl has_any(
    "blob.core.windows.net",
    "drive.google.com",
    "dropbox.com",
    "mega.nz",
    "wetransfer.com",
    "pastebin.com",
    "gofile.io"
)
| project Timestamp, RemoteUrl, RemoteIP, RemotePort, InitiatingProcessFileName
| order by Timestamp desc
```

**Result (this hunt):**
`sacyberrange00.blob.core.windows.net` — Azure Blob Storage endpoint — confirmed as exfiltration destination.

---

## 4. Check for USB / Removable Drive Exfiltration

**Purpose:** Rule out (or confirm) exfiltration via USB or removable drives by checking for file activity on non-standard drive letters (E–J).

```kql
DeviceFileEvents
| where DeviceName == "saranpc2"
| where InitiatingProcessFileName =~ "powershell.exe"
| where InitiatingProcessCommandLine has "exfiltrate.ps1"
| where FolderPath matches regex @"^[E-J]:\\"
| project Timestamp, DeviceName, ActionType, FileName, FolderPath,
    SHA1, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

**How the regex works:**
- `^[E-J]:\\` — matches any file path starting with drive letters E through J
- Drive letters A–D are typically reserved for system/local drives (C: = OS, D: = recovery)
- External USB drives and removable media typically mount as E: or later

**Broader version — check all non-system drive activity:**

```kql
DeviceFileEvents
| where DeviceName == "saranpc2"
| where FolderPath matches regex @"^[E-Z]:\\"
| where ActionType == "FileCreated"
| project Timestamp, FileName, FolderPath, InitiatingProcessFileName
| order by Timestamp desc
```

> 💡 **SOC Tip:** Always run the USB check in insider threat investigations — many analysts skip this step and miss a parallel exfiltration channel. It takes 30 seconds and can be decisive.

**Result (this hunt):**
`<No Results>` — No USB or removable drive exfiltration detected. ✅

---

## 5. Full Kill Chain Correlation Query

**Purpose:** A single query that ties together file creation, process execution, and network events to reconstruct the full exfiltration chain.

```kql
// Step 1: Find archive creation timestamps
let ArchiveEvents =
    DeviceFileEvents
    | where DeviceName == "saranpc2"
    | where FileName endswith ".zip" or FileName endswith ".7z"
    | where InitiatingProcessFileName =~ "powershell.exe"
    | project ArchiveTime = Timestamp, ArchiveFile = FileName, FolderPath;

// Step 2: Find process events within 2 minutes of archive creation
let ProcessContext =
    DeviceProcessEvents
    | where DeviceName == "saranpc2"
    | where FileName =~ "powershell.exe" or FileName =~ "7z.exe"
    | project ProcessTime = Timestamp, FileName, ProcessCommandLine;

// Step 3: Find network events within 2 minutes of archive creation
let NetworkContext =
    DeviceNetworkEvents
    | where DeviceName == "saranpc2"
    | where ActionType == "ConnectionSuccess"
    | where InitiatingProcessFileName =~ "powershell.exe"
    | project NetworkTime = Timestamp, RemoteUrl, RemoteIP, RemotePort;

// Combine all three
ArchiveEvents
| extend TimeWindow = range(ArchiveTime - 2m, ArchiveTime + 2m, 1s)
| join kind=inner ProcessContext on $left.ArchiveTime between ($right.ProcessTime - 2m .. $right.ProcessTime + 2m)
| join kind=inner NetworkContext on $left.ArchiveTime between ($right.NetworkTime - 2m .. $right.NetworkTime + 2m)
| project ArchiveTime, ArchiveFile, ProcessCommandLine, RemoteUrl, RemoteIP
```

> **Note:** This correlation query is resource-intensive and works best scoped to a specific device and time window. Use it after you've already identified the suspect device and approximate timeframe through earlier queries.

---

## 6. Bonus: Detection Engineering Queries

These queries can be deployed as **scheduled detection rules** in Microsoft Sentinel or MDE Custom Detections to catch this behaviour proactively.

### 6.1 — Archive Creation by PowerShell (Exfiltration Staging Alert)

```kql
// Alert: PowerShell creating archive files — potential data staging
DeviceFileEvents
| where ActionType == "FileCreated"
| where FileName endswith ".zip" or FileName endswith ".7z" or FileName endswith ".rar"
| where InitiatingProcessFileName =~ "powershell.exe"
| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessCommandLine
| order by Timestamp desc
```

> **Severity:** High  
> **Recommended action:** Review archive content and correlate with network events for upload activity

---

### 6.2 — PowerShell Outbound to Cloud Storage

```kql
// Alert: PowerShell making outbound connections to cloud storage services
DeviceNetworkEvents
| where ActionType == "ConnectionSuccess"
| where InitiatingProcessFileName =~ "powershell.exe"
| where RemoteUrl has_any(
    "blob.core.windows.net",
    "drive.google.com",
    "dropbox.com",
    "mega.nz",
    "wetransfer.com",
    "onedrive.live.com"
)
| project Timestamp, DeviceName, RemoteUrl, RemoteIP,
    InitiatingProcessCommandLine
| order by Timestamp desc
```

> **Severity:** Critical  
> **Recommended action:** Immediately investigate — archive + cloud upload combination is a confirmed exfiltration pattern

---

### 6.3 — Silent Tool Installation via PowerShell

```kql
// Alert: PowerShell installing known archiving/transfer tools silently
DeviceProcessEvents
| where FileName has_any("7z.exe", "7zip", "winrar.exe", "rar.exe", "curl.exe", "wget.exe")
| where InitiatingProcessFileName =~ "powershell.exe"
| project Timestamp, DeviceName, FileName, ProcessCommandLine,
    InitiatingProcessCommandLine, AccountName
| order by Timestamp desc
```

> **Severity:** High  
> **Recommended action:** Investigate why a standard tool is being silently installed — block via AppLocker if unauthorised

---

### 6.4 — Execution Policy Bypass + External Connection (Combined Indicator)

```kql
// Alert: PowerShell Bypass flag followed by external network connection within 5 minutes
let BypassEvents =
    DeviceProcessEvents
    | where ProcessCommandLine has "-ExecutionPolicy Bypass"
        or ProcessCommandLine has "-ep bypass"
    | project DeviceName, BypassTime = Timestamp, ProcessCommandLine;

DeviceNetworkEvents
| where ActionType == "ConnectionSuccess"
| where isnotempty(RemoteUrl)
| where InitiatingProcessFileName =~ "powershell.exe"
| join kind=inner BypassEvents on DeviceName
| where Timestamp between (BypassTime .. BypassTime + 5m)
| project Timestamp, DeviceName, RemoteUrl, RemoteIP, ProcessCommandLine
```

> **Severity:** Critical  
> **Recommended action:** Isolate device immediately — this combination is a strong indicator of scripted exfiltration

---

### 6.5 — Sensitive File Access Before Archive Creation

```kql
// Detect: Access to sensitive files shortly before archive creation
let SensitiveKeywords = dynamic(["employee", "payroll", "confidential", "salary", "hr", "customer"]);

DeviceFileEvents
| where ActionType == "FileRead" or ActionType == "FileAccessed"
| where FileName has_any(SensitiveKeywords)
| project DeviceName, AccessTime = Timestamp, FileName
| join kind=inner (
    DeviceFileEvents
    | where ActionType == "FileCreated"
    | where FileName endswith ".zip" or FileName endswith ".7z"
    | project DeviceName, ArchiveTime = Timestamp, ArchiveName = FileName
) on DeviceName
| where ArchiveTime between (AccessTime .. AccessTime + 10m)
| project AccessTime, DeviceName, FileName, ArchiveTime, ArchiveName
```

> **Severity:** High  
> **Recommended action:** Correlate with network events to determine if archives were subsequently uploaded

---

## Quick Reference: Key KQL Concepts Used in This Hunt

| Concept | Example |
|---|---|
| Archive file filter | `where FileName endswith ".zip"` |
| Timestamp window pivot | `between ((specificTime - 1m) .. (specificTime + 1m))` |
| Drive letter regex | `where FolderPath matches regex @"^[E-J]:\\"` |
| Process/network correlation | `join kind=inner` on `DeviceName` and time proximity |
| Case-insensitive match | `=~` operator (e.g., `FileName =~ "powershell.exe"`) |
| `let` sub-queries | Define reusable data sets for multi-step correlation |
| `has_any()` with list | Match against multiple cloud storage domains |

---

*Queries authored by: Saran | CyberRange Lab | March 27, 2026*
