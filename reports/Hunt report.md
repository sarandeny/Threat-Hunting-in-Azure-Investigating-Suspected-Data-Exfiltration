# 🕵️ Threat Hunt Report: Suspected Data Exfiltration from a PIP'd Employee

**Hunt ID:** TH-2026-003  
**Analyst:** Saran  
**Date:** March 27, 2026  
**Platform:** Microsoft Defender for Endpoint (MDE)  
**Target Device:** `saranpc2` (John Doe's corporate device)  
**Classification:** TLP:WHITE — Suitable for public sharing (sanitised)

---

## 1. Executive Summary

Following management concerns that a recently PIP'd employee (John Doe) may attempt to steal proprietary company data, a targeted threat hunt was conducted on his corporate device (`saranpc2`) using MDE Advanced Hunting.

The investigation confirmed a **complete data exfiltration kill chain**:

1. A PowerShell script (`exfiltratedata.ps1`) was executed with `-ExecutionPolicy Bypass`
2. The script silently installed **7-Zip** (`7z.exe`) on the device
3. 7-Zip was used to **compress sensitive employee data** (`employee-data.csv`) into archives
4. The archives were **uploaded to an external Azure Blob Storage account** (`sacyberrange00.blob.core.windows.net`) via HTTPS on port 443
5. The HTTPS channel was used deliberately to **blend the exfiltration with legitimate encrypted traffic**

No USB-based exfiltration was found. All findings were escalated to John's manager with a full evidence package.

**Verdict: Data Exfiltration Confirmed. Escalated to Management.**

---

## 2. Preparation

### 2.1 Hunt Objective

Investigate whether John Doe — a recently PIP'd employee in a sensitive department — has used his corporate device (`saranpc2`) to steal or exfiltrate proprietary company data.

### 2.2 Threat Hypothesis

> *"John may be using his local administrator privileges to silently install archiving tools, compress sensitive company data, and transfer it to an external personal or cloud destination before resigning."*

**Supporting risk factors:**
- John has **local admin rights** — can install any software silently
- **No application allowlist** — unrestricted application execution
- John has **legitimate access** to sensitive data as part of his role, making access anomalies harder to detect
- Insider threats often use **legitimate tools** (7-Zip, PowerShell, cloud storage) specifically to evade detection

### 2.3 Key Data Sources Identified

| Table | Purpose |
|---|---|
| `DeviceFileEvents` | Detect archive creation (`.zip`, `.7z`) and file access on sensitive data |
| `DeviceProcessEvents` | Identify processes used to install tools and compress data |
| `DeviceNetworkEvents` | Confirm outbound connections to external exfiltration destinations |

### 2.4 Scope

- **Primary device:** `saranpc2` (John Doe's assigned corporate device)
- **Time window:** Last 30 days
- **Secondary check:** USB/removable drive exfiltration

---

## 3. Data Collection

### 3.1 Verify Log Availability

The following tables were confirmed to contain recent, relevant logs for `saranpc2`:

- ✅ `DeviceFileEvents` — Active with file creation/modification data
- ✅ `DeviceProcessEvents` — Active with process execution data
- ✅ `DeviceNetworkEvents` — Active with network connection data

---

## 4. Data Analysis

### 4.1 Archive File Detection

The first query searched `DeviceFileEvents` for any `.zip` file activity on `saranpc2` — a primary indicator of data staging for exfiltration.

**Query Used:**
```kql
DeviceFileEvents
| where DeviceName == "saranpc2"
| where FileName endswith ".zip"
```

**Finding:**

Multiple `.zip` file creation events were returned. While some appeared to be routine backup activity, several instances stood out as unusual — archives being created in non-standard locations, initiated by `powershell.exe`, involving files with names consistent with sensitive HR or employee data.

![DeviceFileEvents showing .zip file creation activity on saranpc2](../assets/screenshots/01-zip-file-events.png)

> **SOC Analyst Note:** Not all archive creation is malicious — backup jobs create `.zip` files routinely. The key is to look at *what* is being archived, *where* the archive is saved, and *what process* created it. PowerShell creating a `.zip` of `employee-data.csv` in `C:\programdata\` is very different from a backup agent creating archives in a designated backup directory.

### 4.2 Timestamped Pivot to Process Events

Taking a timestamp from one of the suspicious `.zip` creation events, a pivot was made to `DeviceProcessEvents` within a ±1 minute window to identify the responsible process.

**Query Used:**
```kql
let VMName = "saranpc2";

DeviceProcessEvents
| where Timestamp between ((specificTime - 1m) .. (specificTime + 1m))
| where DeviceName == VMName
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, ProcessCommandLine
```

**Finding:**

Around the same time as the archive creation, a PowerShell process was observed that:
1. **Silently downloaded and installed 7-Zip** (`7z.exe`) onto the device
2. **Used 7-Zip to compress** employee data files into archives

![DeviceProcessEvents — PowerShell installing 7-Zip and archiving employee data](../assets/screenshots/02-process-events-7zip.png)

The command line revealed the execution of `exfiltratedata.ps1` with `-ExecutionPolicy Bypass`, confirming deliberate circumvention of PowerShell security controls.

### 4.3 Network Connection Analysis

Using the same timestamp, a pivot was made to `DeviceNetworkEvents` to check for outbound connections around the time of the archive creation.

**Finding:**

An outbound **HTTPS connection (port 443)** was observed from `powershell.exe` executing `exfiltratedata.ps1` to:

| Field | Value |
|---|---|
| **Destination** | `sacyberrange00.blob.core.windows.net` |
| **Destination IP** | `20.60.181.193` |
| **Port** | `443` (HTTPS) |
| **Action** | `ConnectionSuccess` |
| **Initiating Process** | `powershell.exe` |
| **Script** | `exfiltratedata.ps1` with `-ExecutionPolicy Bypass` |

![DeviceNetworkEvents — outbound HTTPS connection to Azure Blob Storage](../assets/screenshots/03-network-exfiltration.png)

**Why HTTPS to Azure Blob Storage is concerning:**
- Port 443/HTTPS traffic is almost universally allowed through firewalls and proxies
- Azure Blob Storage is a legitimate Microsoft service — not blocked by most egress filters
- The encrypted channel prevents content inspection by traditional DLP tools
- The combination of script name (`exfiltratedata`), PowerShell bypass, and cloud storage destination leaves no reasonable alternative interpretation

### 4.4 Script Content Inspection

The analyst logged directly into `saranpc2` and inspected `exfiltratedata.ps1` at `C:\programdata\`.

![exfiltratedata.ps1 script content — automated archive and upload to Azure Blob](../assets/screenshots/04-exfiltrate-script-content.png)

The script confirmed a fully automated exfiltration chain — archiving target files with 7-Zip, then uploading to the Azure Blob Storage endpoint.

### 4.5 USB / Removable Drive Check

To ensure no alternative exfiltration vector was missed, `DeviceFileEvents` was queried specifically for file activity on removable drive letters (E through J).

**Query Used:**
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

**Result:** `<No Results>`

✅ No USB or removable drive exfiltration detected.

---

## 5. Investigation

### 5.1 Full Kill Chain Reconstruction

| Step | Action | Evidence Source |
|---|---|---|
| 1 | `exfiltratedata.ps1` downloaded to `C:\programdata\` | `DeviceFileEvents` |
| 2 | Script executed via `powershell.exe -ExecutionPolicy Bypass` | `DeviceProcessEvents` |
| 3 | 7-Zip silently installed by the script | `DeviceProcessEvents` (7z.exe install) |
| 4 | `employee-data.csv` and other files compressed into `.zip`/`.7z` archives | `DeviceFileEvents` (archive creation) |
| 5 | Archives uploaded to `sacyberrange00.blob.core.windows.net` via HTTPS | `DeviceNetworkEvents` (ConnectionSuccess) |
| 6 | Exfiltration channel: encrypted HTTPS on port 443 to Azure Blob Storage | `DeviceNetworkEvents` |

### 5.2 Why This Was Hard to Detect

| Factor | Impact |
|---|---|
| **Legitimate tools used** | 7-Zip and PowerShell are standard IT tools — not flagged by AV |
| **HTTPS traffic** | Encrypted channel prevents content inspection |
| **Azure Blob Storage** | Trusted Microsoft domain — not blocked by egress filters |
| **No DLP in place** | No policy to detect large outbound data transfers |
| **Admin rights** | Silently installed tools without any UAC prompt or alert |

### 5.3 MITRE ATT&CK Correlation

| TTP | Technique | Evidence |
|---|---|---|
| **T1560.001** | Archive via Utility | `7z.exe` compressing `employee-data.csv` |
| **T1059.001** | PowerShell | `powershell.exe -ExecutionPolicy Bypass -File exfiltratedata.ps1` |
| **T1071.001** | Web Protocols (HTTPS) | Outbound port 443 to Azure Blob Storage |
| **T1048** | Exfiltration Over Alternative Protocol | Cloud storage as exfil channel |
| **T1027** | Obfuscated Files or Information | Compression prior to transfer |
| **T1070.004** | File Deletion (Potential) | Not observed but common post-exfil step |

See [`mitre/ttp-mapping.md`](../mitre/ttp-mapping.md) for full analysis.

---

## 6. Response

### 6.1 Actions Taken

| Action | Status | Detail |
|---|---|---|
| **Escalated to management** | ✅ Complete | Full evidence package — archive events, network connections, script content — provided to John's manager |
| **USB exfiltration ruled out** | ✅ Complete | Removable drive regex check returned no results |
| **Evidence preserved** | ✅ Complete | All logs retained from `DeviceFileEvents`, `DeviceProcessEvents`, `DeviceNetworkEvents` |

### 6.2 Recommended Next Steps

| Recommendation | Priority | Detail |
|---|---|---|
| **Disable John's account** | 🔴 Immediate | Pending HR/legal guidance — prevent further access |
| **Preserve device for forensics** | 🔴 Immediate | Do not wipe `saranpc2` — potential legal evidence |
| **Notify legal/HR** | 🔴 High | Data theft may constitute a legal matter |
| **Revoke cloud access** | 🔴 High | Any corporate cloud credentials John holds should be rotated immediately |
| **Implement DLP** | 🟠 Medium | Deploy Data Loss Prevention policies to detect large outbound transfers |
| **Egress filtering** | 🟠 Medium | Restrict outbound connections to approved domains only |
| **Remove local admin rights** | 🟠 Medium | Standard users should not have admin rights on corporate devices |
| **Enable PowerShell logging** | 🟠 Medium | Script Block Logging + Module Logging via GPO |
| **Application allowlisting** | 🟡 Low | Block unauthorised tools (e.g., 7-Zip, unapproved archivers) via AppLocker/WDAC |

---

## 7. Documentation

### 7.1 Evidence Summary

| Evidence | Source |
|---|---|
| `.zip` file creation events linked to sensitive files | `DeviceFileEvents` |
| 7-Zip silently installed via PowerShell | `DeviceProcessEvents` |
| `exfiltratedata.ps1` executed with Bypass flag | `DeviceProcessEvents` (CommandLine) |
| Outbound HTTPS to Azure Blob Storage (`20.60.181.193:443`) | `DeviceNetworkEvents` |
| `ConnectionSuccess` — data confirmed uploaded | `DeviceNetworkEvents` (ActionType) |
| Script content confirming automated archive + upload chain | Direct device inspection |
| No USB exfiltration | `DeviceFileEvents` (regex drive check — no results) |

### 7.2 Chain of Custody Note

> In a real incident, all evidence should be captured with timestamps, query text, and analyst attribution before any remediation takes place. Screenshots of query results, exported log data, and the script content should be compiled into a formal evidence package suitable for HR and legal review.

---

## 8. Improvement

### 8.1 Detection Gaps Identified

| Gap | Impact | Fix |
|---|---|---|
| No DLP policy | Exfiltration completed undetected | Implement Microsoft Purview DLP |
| No egress filtering | Azure Blob Storage connection allowed freely | Restrict outbound to approved domains |
| No PowerShell logging | Script execution not alerted on | Enable Script Block Logging via GPO |
| Admin rights for standard user | 7-Zip installed silently | Apply least privilege — remove local admin |
| No archive creation alert | Staging went undetected | Alert on `.zip`/`.7z` creation by `powershell.exe` |

### 8.2 Detection Engineering Opportunities

This hunt produced multiple high-value detection rules — see [`queries/kql-queries.md`](../queries/kql-queries.md) for full KQL:

1. **Archive Creation by PowerShell** — alert when `powershell.exe` creates `.zip` or `.7z` files
2. **PowerShell Outbound to Cloud Storage** — alert when PowerShell makes external HTTPS connections
3. **Sensitive File Access + Archive Chain** — correlate file access → archive creation → network upload
4. **Execution Policy Bypass + External Connection** — combined indicator of scripted exfiltration

### 8.3 Process Improvement

- **Trigger proactive hunts on HR events** — a PIP, termination notice, or disciplinary action should automatically trigger a background review of the employee's endpoint activity
- **Correlate across all three tables** (File + Process + Network) as a standard playbook step — no single table tells the full story
- **Establish a baseline** for archive creation on sensitive devices — deviations from baseline are easier to alert on

---

*Report authored by: Saran | CyberRange Lab | March 27, 2026*
