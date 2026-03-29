# 📋 Incident Response Playbook
## Scenario: Suspected Insider Threat — Data Exfiltration

**Playbook ID:** IR-PB-003  
**Version:** 1.0  
**Last Updated:** March 27, 2026  
**Classification:** TLP:WHITE

---

## Purpose

This playbook provides a structured, repeatable process for investigating suspected insider threats involving unauthorised data collection and exfiltration. It is designed for **Tier 1 and Tier 2 SOC analysts** working with Microsoft Defender for Endpoint (MDE) telemetry, and is intended to be initiated in coordination with HR and Legal.

> ⚠️ **Important:** Insider threat investigations have legal and HR implications. Always notify your manager and loop in HR/Legal before taking any visible action on the employee's device. Evidence preservation is the top priority.

---

## Trigger Conditions

Initiate this playbook when **any of the following** are true:

- [ ] HR or management reports that an employee may be planning to steal data
- [ ] A DLP alert fires for large outbound data transfer from a corporate device
- [ ] Detection rule fires for archive creation (`7z.exe`, `.zip`, `.7z`) by PowerShell on an endpoint
- [ ] Unusual outbound HTTPS connections detected from a user's device to cloud storage
- [ ] A departing or disgruntled employee's device shows anomalous file or network activity
- [ ] An alert fires for PowerShell executing with `-ExecutionPolicy Bypass` to external destinations

---

## Severity Classification

| Severity | Criteria |
|---|---|
| 🔴 **Critical** | Exfiltration confirmed — data successfully transferred to external destination |
| 🟠 **High** | Data staged (archives created) but upload not yet confirmed |
| 🟡 **Medium** | Suspicious file access to sensitive data — no archive or upload yet |
| 🟢 **Low** | Anomalous behaviour flagged but no sensitive data access confirmed |

**This hunt:** 🔴 Critical — Exfiltration confirmed via Azure Blob Storage.

---

## ⚠️ Pre-Investigation Checklist

Before starting any queries or taking any action:

- [ ] **Notify your manager** — insider threat investigations require senior oversight
- [ ] **Loop in HR** — any action taken may be used in disciplinary/legal proceedings
- [ ] **Loop in Legal** — data theft may constitute criminal activity depending on jurisdiction
- [ ] **Do NOT confront the employee** — this could cause them to destroy evidence or accelerate exfiltration
- [ ] **Do NOT lock the account yet** — this alerts the suspect; wait for legal guidance unless imminent risk
- [ ] **Document everything** — all queries, timestamps, and findings must be recorded with analyst attribution

---

## Phase 1: Initial Scoping

**Estimated time: 15–30 minutes**

### Step 1.1 — Identify the Device

Confirm the employee's assigned corporate device name from HR/IT asset records.

```kql
DeviceInfo
| where DeviceName == "<EMPLOYEE_DEVICE>"
| summarize LastSeen = max(Timestamp) by DeviceName, LoggedOnUsers, PublicIP
```

- [ ] Confirm device is active and reporting to MDE
- [ ] Note any other logged-on users (shared device?)

### Step 1.2 — Check for Archive File Creation

```kql
DeviceFileEvents
| where DeviceName == "<EMPLOYEE_DEVICE>"
| where FileName endswith ".zip"
    or FileName endswith ".7z"
    or FileName endswith ".rar"
    or FileName endswith ".tar"
| project Timestamp, ActionType, FileName, FolderPath,
    InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

- [ ] Are archives being created? When did it start?
- [ ] What process is creating them? (`InitiatingProcessFileName`)
- [ ] Do the archive names or paths suggest sensitive data?
- [ ] Note timestamps for pivoting

### Step 1.3 — Assign Severity

Use the classification table above. If archives are being created by PowerShell → minimum 🟠 High.

---

## Phase 2: Kill Chain Reconstruction

**Estimated time: 30–60 minutes**

### Step 2.1 — Pivot to Process Events

Using a timestamp from Step 1.2, investigate what process was responsible.

```kql
let TargetDevice = "<EMPLOYEE_DEVICE>";
let IncidentTime = datetime(YYYY-MM-DDTHH:MM:SSZ); // From archive creation timestamp

DeviceProcessEvents
| where DeviceName == TargetDevice
| where Timestamp between ((IncidentTime - 1m) .. (IncidentTime + 1m))
| project Timestamp, FileName, ProcessCommandLine, AccountName, InitiatingProcessFileName
| order by Timestamp asc
```

- [ ] Is a script (e.g., `exfiltratedata.ps1`) being executed?
- [ ] Was `-ExecutionPolicy Bypass` used?
- [ ] Was a tool (e.g., `7z.exe`) silently installed?
- [ ] Which account ran this?

### Step 2.2 — Check for Outbound Network Connections

Using the same timestamp, check for upload activity.

```kql
let TargetDevice = "<EMPLOYEE_DEVICE>";
let IncidentTime = datetime(YYYY-MM-DDTHH:MM:SSZ);

DeviceNetworkEvents
| where DeviceName == TargetDevice
| where Timestamp between ((IncidentTime - 1m) .. (IncidentTime + 1m))
| where ActionType == "ConnectionSuccess"
| project Timestamp, RemoteUrl, RemoteIP, RemotePort,
    InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp asc
```

- [ ] Is there an outbound connection to cloud storage or file sharing services?
- [ ] Was `ConnectionSuccess` recorded? (Confirms data was actually sent)
- [ ] Note the destination URL/IP for threat intel lookup

**Common exfiltration destinations to check:**

```kql
DeviceNetworkEvents
| where DeviceName == "<EMPLOYEE_DEVICE>"
| where RemoteUrl has_any(
    "blob.core.windows.net", "drive.google.com",
    "dropbox.com", "mega.nz", "wetransfer.com",
    "gofile.io", "pastebin.com", "onedrive.live.com"
)
| where ActionType == "ConnectionSuccess"
```

### Step 2.3 — Check for USB / Removable Drive Exfiltration

```kql
DeviceFileEvents
| where DeviceName == "<EMPLOYEE_DEVICE>"
| where FolderPath matches regex @"^[E-Z]:\\"
| where ActionType == "FileCreated"
| project Timestamp, FileName, FolderPath, InitiatingProcessFileName
| order by Timestamp desc
```

- [ ] Any file activity on removable drive letters?
- [ ] This rules out (or confirms) a parallel exfiltration channel

### Step 2.4 — Check for Email-Based Exfiltration

If the environment includes email telemetry:
- Review sent emails from the employee's account for large attachments
- Check for forwarding rules set up on their mailbox
- Look for emails to personal addresses (Gmail, Yahoo, Hotmail)

---

## Phase 3: Evidence Preservation

> **Do this before any containment action.** Once you isolate the device, you may not be able to collect additional evidence without Live Response access.

### Step 3.1 — Export Key Logs

Export the following from MDE Advanced Hunting (save with timestamps and query text):

- [ ] `DeviceFileEvents` — archive creation events
- [ ] `DeviceProcessEvents` — script execution and tool installation
- [ ] `DeviceNetworkEvents` — outbound connection to exfiltration destination
- [ ] `DeviceLogonEvents` — account activity during the incident window

### Step 3.2 — Screenshot Evidence

Capture screenshots of:
- [ ] Archive file creation query results
- [ ] Process command line showing script name and bypass flag
- [ ] Network connection to exfiltration destination (URL, IP, ActionType)
- [ ] Script content (if accessible via Live Response or device login)

### Step 3.3 — Record File Hashes

```kql
DeviceFileEvents
| where DeviceName == "<EMPLOYEE_DEVICE>"
| where FileName has_any("exfiltrate", ".zip", ".7z")
| project Timestamp, FileName, FolderPath, SHA1, MD5
```

File hashes provide a cryptographically verifiable record of what existed on the device at a given time — essential for legal proceedings.

---

## Phase 4: Containment

Only proceed after confirming with your manager, HR, and Legal.

### Step 4.1 — Isolate the Device

**Via MDE Portal:**
1. Navigate to the device page
2. **Device actions** → **Isolate device**
3. Select **Full isolation** (blocks all network traffic except MDE)
4. Document the time of isolation

### Step 4.2 — Do NOT Wipe the Device

The device is potential legal evidence. Do not:
- ❌ Reimage or rebuild the device
- ❌ Delete files or clear logs
- ❌ Run scripts that modify the filesystem

### Step 4.3 — Account Suspension (With Legal Approval)

Once Legal confirms:
- [ ] Disable the employee's AD/Azure AD account
- [ ] Revoke any active sessions (O365, VPN, cloud apps)
- [ ] Rotate any shared credentials the employee may have had access to
- [ ] Revoke API keys or service account access if applicable

---

## Phase 5: Escalation & Reporting

### Step 5.1 — Management Escalation Package

Prepare a concise summary for management/HR containing:

```
INCIDENT SUMMARY
================
Date: _______________
Device: _______________
Employee: _______________

WHAT HAPPENED:
A PowerShell script was executed on [device] that:
1. Silently installed [archiving tool]
2. Compressed [what files] into archives
3. Uploaded the archives to [destination]

EVIDENCE:
- Archive creation: [timestamp, screenshot]
- Process execution: [command line, screenshot]
- Network upload: [destination, IP, port, screenshot]
- USB check: [clean / found]

RECOMMENDED ACTIONS:
- [ ] Disable employee account
- [ ] Preserve device for forensics
- [ ] Notify Legal re: potential data theft
- [ ] Assess scope of data accessed
```

### Step 5.2 — Legal Notification Checklist

- [ ] Volume and type of data exfiltrated — does this trigger regulatory notification?
- [ ] Was customer or employee PII involved? (GDPR, HIPAA, etc.)
- [ ] Preserve chain of custody for all evidence
- [ ] Confirm legal hold on the device and associated accounts

---

## Phase 6: Post-Incident Hardening

| Action | Tool | Priority |
|---|---|---|
| Implement DLP policies | Microsoft Purview DLP | 🔴 High |
| Egress filtering for cloud storage | Firewall / Proxy | 🔴 High |
| PowerShell Script Block Logging | GPO | 🔴 High |
| Remove local admin rights from standard users | AD GPO | 🟠 Medium |
| Application allowlisting (block 7z, WinRAR for non-IT) | AppLocker / WDAC | 🟠 Medium |
| Alert on archive creation by PowerShell | Sentinel / MDE Custom Detection | 🟠 Medium |
| HR-triggered endpoint review process | SOC Process | 🟡 Low |
| Insider threat training for managers | HR | 🟡 Low |

---

## Key Difference: Insider Threat vs. External Attack

| Factor | Insider Threat | External Attack |
|---|---|---|
| **Access** | Legitimate — already has credentials and data access | Must establish foothold first |
| **Tools** | Legitimate tools (7-Zip, PowerShell) — harder to detect | May use custom malware |
| **Motivation** | Clear (financial, revenge, new employer) | Varies |
| **Detection** | Behaviour anomaly detection, DLP | IOC-based, network detection |
| **Response** | HR/Legal involvement required | Technical containment first |
| **Escalation** | Manager → HR → Legal → CISO | SOC → IR team → CISO |

---

*Playbook authored by: Saran | CyberRange Lab | March 27, 2026*  
*Review cycle: Quarterly or after each major insider threat incident*
