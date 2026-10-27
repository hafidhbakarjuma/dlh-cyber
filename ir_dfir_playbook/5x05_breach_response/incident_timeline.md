# Incident Timeline: IR-2026-0420-01

| Timestamp (UTC) | Type | Actor | Description | Source | Certainty |
|------------------|------|-------|-------------|--------|-----------|
| 2026-04-17T... | EVIDENCE | Attacker | Spearphishing email with malicious Word document macro delivered to MedDefense on-call clinical coordinator. | Email / Proxy Logs | High |
| 2026-04-17T... | EVIDENCE | Attacker | Macro executes PowerShell downloader, retrieving Cobalt Strike beacon from squatted Microsoft CDN domain; 72-hour dwell period begins. | Sysmon / Proxy Logs | High |
| 2026-04-20T19:43 | OBSERVATION | Mike Torres | Received user report from Site A on-call nurse that workstation (`cs-ws-101`) is sluggish and desktop files look altered; observed scheduling server hammering disk and SIEM service installation alerts on three unfamiliar hosts. | Phone Call / Torres | High |
| 2026-04-20T19:52 | DECISION / ACTION | On-Call IR Analyst | Declared incident IR-2026-0420-01, assigned SEV1 severity, activated IR Playbook, and initiated emergency response bridge. | IR Record | High |
| 2026-04-20T19:54 | COMMUNICATION | On-Call IR Analyst | Notified CISO and Legal Counsel regarding potential unauthorized access to 1,847 patient files. | Notification Log | High |
| 2026-04-20T19:56 | ACTION | On-Call IR Analyst | Mobilized full IR and Forensics team to active incident channel. | Communication Log | High |
| 2026-04-20T20:05 | COMMUNICATION | On-Call IR Analyst | Sent formal executive status update to Dr. Morales and leadership team. | Communication Log | High |
