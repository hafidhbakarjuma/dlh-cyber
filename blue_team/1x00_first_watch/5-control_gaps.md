# MedDefense Health Systems — The Missing Pieces
## Control Gap Analysis

**Prepared by:** Junior Security Analyst
**Prepared for:** James Chen, Deputy CISO
**Source:** Control Summary Matrix (Task 4), source artifacts, prior incident log and walk-through observations
**Purpose:** Identify systemic gaps in the control framework by analyzing what is absent, not only what is present.

---

## Gap Inventory

---

**Gap ID:** G-001
**Gap Description:** No documented incident response plan, escalation procedure, or containment process exists anywhere in the organization. When incidents occur, response is improvised by whichever staff happen to be involved.
**Category x Function Missing:** Administrative / Corrective
**Affected Asset(s) or Zone:** Entire organization — no asset or incident type is covered by a formal response process.
**Risk if Unaddressed:** Response time and quality remain dependent on who happens to be available rather than a repeatable procedure. This already manifested directly: the January ransomware response was described as James, Sarah, and Marcus improvising for four days, and the ongoing billing-srv-01 cryptominer was initially misdiagnosed as a hardware capacity issue for weeks. Every CIA pillar is at greater risk for longer during any future incident, since containment and recovery speed both depend on process, not improvisation.
**Evidence:** Task 4 matrix shows the Administrative/Corrective cell empty; Marcus's notes state directly "No formal incident response plan exists"; the January incident response is described as ad hoc.

---

**Gap ID:** G-002
**Gap Description:** No administrative process exists for actively detecting policy violations, anomalous behavior, or emerging threats through non-technical means — no phishing simulation program, no periodic access/audit review, no scheduled security review cadence.
**Category x Function Missing:** Administrative / Detective
**Affected Asset(s) or Zone:** Entire organization, particularly the human layer (staff behavior, credential misuse, policy compliance).
**Risk if Unaddressed:** Weaknesses that only become visible through active human-process checks — such as the shared PACS login Marcus reported and reported going unaddressed, or low training completion at Westside (58%) — persist indefinitely because nothing in the control framework is designed to surface them proactively.
**Evidence:** Task 4 matrix shows the Administrative/Detective cell empty; Artifact 7 confirms no phishing simulation campaigns have ever been conducted; no audit or review process is described in any artifact.

---

**Gap ID:** G-003
**Gap Description:** Antivirus/endpoint protection (Sophos) is deployed and functioning on Windows workstations, but explicitly does not cover any Linux server — including ehr-srv-01, ehr-db-01, billing-srv-01, web-srv-01, and backup-srv-01 — nor any Windows server, due to licensing limitations.
**Category x Function Missing:** Technical / Preventive (with a corresponding Detective gap on the same assets)
**Affected Asset(s) or Zone:** Every Linux and Windows server at Central, including the EHR application, EHR database, billing system, public web server, and backup infrastructure — arguably the organization's most critical technical assets.
**Risk if Unaddressed:** This is not theoretical — it is the confirmed root cause of the cryptominer persisting undetected on billing-srv-01 for approximately two weeks. Any malware targeting server infrastructure specifically (as opposed to end-user workstations) currently faces zero endpoint-level prevention or detection at all.
**Evidence:** Task 4 matrix (C-008 covers workstations only); Artifact 4 explicitly states Windows servers and Linux servers are "NOT covered"; directly confirmed by the billing-srv-01 diagnostics (Task 3 analysis).

---

**Gap ID:** G-004
**Gap Description:** Logging exists on individual systems (firewall, SSH, Windows Event Viewer, Linux syslog, Apache, EHR audit log), but nothing aggregates, correlates, or actively alerts on this data. Logs are reviewed manually and only after a problem is already suspected.
**Category x Function Missing:** Technical / Detective (functionally absent despite individual components existing)
**Affected Asset(s) or Zone:** Entire technical environment — no system benefits from proactive, automated detection.
**Risk if Unaddressed:** A genuine intrusion can persist for an extended period without triggering any alert, because no mechanism exists to notice it unless a human happens to go looking. The billing-srv-01 miner's binary was dated 14 days prior to discovery — meaning a live, unauthorized process ran undetected for two weeks despite multiple log sources theoretically containing evidence of it.
**Evidence:** Artifact 8 confirms no centralized log management system and no automated alerting exists; Marcus had begun researching a SIEM (Wazuh) but never implemented it.

---

**Gap ID:** G-005
**Gap Description:** No network segmentation exists at Central. All workstations, servers, and medical IoT devices — including patient monitors and infusion pumps — share a single flat /16 network with no VLANs.
**Category x Function Missing:** Technical / Preventive
**Affected Asset(s) or Zone:** Entire Central network — critically, this places life-safety medical devices (infusion pumps, patient monitors) on the same reachable segment as general-purpose workstations and servers.
**Risk if Unaddressed:** Compromise of any single device anywhere on the network — a workstation via phishing, a server via an unpatched web application, an unmanaged personal laptop (as in Incident F) — provides a direct path to every other asset on the network, including devices whose manipulation could cause direct patient harm.
**Evidence:** Task 0 network topology findings; Marcus's notes explicitly flag the flat 10.10.0.0/16 network as a known, unaddressed issue ("planned for next fiscal year" for over four months); Task 3 Observation 4 (vital signs monitor on the same IP range as nurse station workstations).

---

**Gap ID:** G-006
**Gap Description:** No physical detective control (camera) exists anywhere near the server room, network closets, or administrative wing — the four cameras that exist at Central cover only entrances and the parking garage.
**Category x Function Missing:** Physical / Detective
**Affected Asset(s) or Zone:** Server room (housing nearly all critical servers), the unlocked second-floor network closet, and the administrative/IT wing.
**Risk if Unaddressed:** Unauthorized physical access to the areas housing the organization's most critical infrastructure would go completely unrecorded, meaning MedDefense would have no evidentiary basis to even determine that a physical breach occurred, let alone who was responsible.
**Evidence:** Task 4 matrix (C-015/C-016 cover entrances only); Artifact 6 explicitly states "No cameras in server room area, network closets or administrative wing"; corroborated directly by Task 3 Observations 1 and 2.

---

**Gap ID:** G-007
**Gap Description:** The backup control (Veeam nightly job) exists but excludes several systems entirely (pacs-srv-01, ad-dc-02, print-srv-01, the Westside server, medical device configurations, O365 data) and has never undergone a full disaster recovery test — only one partial single-server restore eight months ago, which took six hours.
**Category x Function Missing:** Technical / Corrective (control exists but does not adequately cover critical assets or guarantee restoration capability)
**Affected Asset(s) or Zone:** PACS imaging data, secondary domain controller, Westside Clinic systems, all O365 data (email, SharePoint, OneDrive), and — for covered systems — actual recoverability at scale, which remains unverified.
**Risk if Unaddressed:** A significant incident affecting any excluded system has no recovery path at all. Even for covered systems, an untested full-scale recovery means MedDefense does not actually know how long real recovery would take or whether it would succeed — a gap directly evidenced by the fact that the January ransomware recovery relied on a backup that was three weeks old due to a separate, unrelated scheduling failure.
**Evidence:** Artifact 5 explicitly lists exclusions and states "Full DR test: Never performed"; Incident A's backup was stale due to a misconfigured cron job, demonstrating the corrective control had already failed once in practice.

---

## Pattern Analysis

Looking at the gaps as a whole, MedDefense's security posture is heavily **prevention-oriented and severely under-built for detection and correction**. Nearly every control identified in Task 4 is Preventive (firewall rules, SSH hardening, password policy, antivirus, VPN restrictions), while Detective controls are sparse and largely non-functional in practice (isolated, non-correlated logs; camera coverage that misses every critical zone), and Corrective controls are almost nonexistent beyond a single, partially-tested backup job. This implies that MedDefense is structurally reliant on its preventive controls simply not failing — and when they do fail, as they already have twice on the same server, the organization has very limited ability to detect the breach quickly (the miner ran undetected for two weeks) and even less ability to respond and recover through any repeatable process (both real incidents were handled ad hoc, and the backup system's own recovery was never fully validated). An organization this weighted toward prevention alone is exposed almost entirely to any threat that gets past its first line of defense.
