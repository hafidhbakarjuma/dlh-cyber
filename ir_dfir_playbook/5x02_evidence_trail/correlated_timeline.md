# Correlated Incident Timeline: LH-2026-0414-01

| Timestamp (UTC) | Source | Event | ATT&CK | Certainty | Evidence Ref |
| :--- | :--- | :--- | :--- | :--- | :--- |
| 2026-04-13T21:42:10Z | proxy_log.jsonl | Credential phishing link clicked (`meddefense-portal.com/login`) by `dmarsh` | T1566.002 | confirmed | proxy_log line 142 |
| 2026-04-13T21:43:05Z | proxy_log.jsonl | Credentials submitted to typosquat phishing domain | T1539 | confirmed | proxy_log line 148 |
| 2026-04-13T22:05:12Z | ad_auth_log.jsonl | Attacker VPN access and Domain Auth using compromised `dmarsh` credentials | T1078.002 | confirmed | ad_auth_log line 89 |
| 2026-04-13T22:14:28Z | ART-002 (wst-ws-031.mem) | `powershell.exe` execution with Base64-encoded payload | T1059.001 | confirmed | ART-002-M01 |
| 2026-04-13T22:14:32Z | ART-001 (wst-ws-031.dd) | Malicious staging file `update.xml` dropped to `AppData\Local\Temp\` | T1105 | confirmed | ART-001-F01 |
| 2026-04-13T22:14:35Z | ART-002 (wst-ws-031.mem) | `msbuild.exe` spawned by PowerShell executing `update.xml` (C2 beacon starts) | T1127.001 | confirmed | ART-002-M01, ART-002-M02 |
| 2026-04-13T22:15:01Z | ART-001 (wst-ws-031.dd) | Second-stage binary `updater.exe` dropped to `AppData\Local\Temp\` | T1105 | confirmed | ART-001-F02, ART-001-E02 |
| 2026-04-13T22:18:02Z | ART-001 (wst-ws-031.dd) | Run key persistence installed (`WindowsUpdateSvc` pointing to `updater.exe`) | T1547.001 | confirmed | ART-001-R01 |
| 2026-04-13T22:18:40Z | ART-001 (wst-ws-031.dd) | Scheduled task persistence installed (`MedDefenseUpdate`) | T1053.005 | confirmed | ART-001-F03, ART-001-R02 |
| 2026-04-13T22:22:15Z | ART-002 (wst-ws-031.mem) | LSASS memory access by `msbuild.exe`; NTLM hashes and Kerberos tickets exposed | T1003.001 | confirmed | ART-002-M04 |
| 2026-04-13T22:30:04Z | ad_auth_log.jsonl | Kerberos TGS request issued for service `cifs/WST-WS-017` using compromised ticket | T1558 | confirmed | ad_auth_log line 215 |
| 2026-04-13T22:32:10Z | ART-003 (wst-ws-017.mem) | Lateral movement logon to `WST-WS-017` via SMB/PsExec (`psexesvc.exe`) | T1021.002 | confirmed | ART-003-M01 |
| 2026-04-13T22:33:45Z | proxy_log.jsonl | Second C2 beacon established from `WST-WS-017` to external IP | T1071.001 | confirmed | proxy_log line 312 |
| 2026-04-13T22:45:18Z | ad_auth_log.jsonl | Kerberos TGS request issued for service `cifs/LIS-WSIDE-01` | T1558 | confirmed | ad_auth_log line 284 |
| 2026-04-13T22:47:02Z | ad_auth_log.jsonl | Successful network share logon to Laboratory Information System (`LIS-WSIDE-01`) | T1021.002 | confirmed | ad_auth_log line 301 |
| 2026-04-13T22:50:11Z | proxy_log.jsonl | Exfiltration/Access: 14 patient lab report PDFs accessed and read on `LIS-WSIDE-01` | T1005 | confirmed | proxy_log line 405 |
