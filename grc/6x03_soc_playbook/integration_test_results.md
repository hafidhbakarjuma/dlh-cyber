
# MedDefense SOC Automation - Integration Test Results

**Date / Time:** 2026-04-28  
**Environment:** MedDefense SOC Lab Container (Ubuntu 22.04+, Python 3.10+)  
**Scope:** End-to-end integration testing of `enrich_ioc.py`, `case_manager.py`, `playbook_phishing_triage.py`, and `playbook_credential_exposure.py`.

---

## Test Summary

| Test # | Alert ID | Playbook | Scenario Description | Expected Verdict / Severity | Actual Verdict / Severity | Result |
| :---: | :--- | :--- | :--- | :--- | :--- | :---: |
| **1** | ALT-20260428-001 | Phishing Triage | Known malicious C2 IP & typosquat domain | ESCALATE / Critical | ESCALATE / Critical | **PASS** |
| **2** | ALT-20260428-002 | Phishing Triage | Unknown external sender / unlisted domain | REVIEW / High | REVIEW / High | **PASS** |
| **3** | ALT-20260428-003 | Phishing Triage | Internal sender (private IP range) | CLOSE / Low | CLOSE / Low | **PASS** |
| **4** | ALT-20260428-007 | Credential Exposure | LSASS dump from C2 IP by Domain Admin | ESCALATE / Critical (Isolation Queued) | ESCALATE / Critical (Isolation Queued) | **PASS** |
| **5** | ALT-20260428-009 | Credential Exposure | Pass the Hash from internal IP by standard user | REVIEW / Medium (No Isolation) | REVIEW / Medium (No Isolation) | **PASS** |

---

## Detailed Test Execution

### Test 1: ALT-20260428-001 (Phishing Triage - Malicious C2)
* **Scenario:** Phishing email originating from a malicious external IP and typosquatted domain associated with Cobalt Strike infrastructure.
* **Command Executed:**
  ```bash
  python3 playbook_phishing_triage.py alerts/phishing/ALT-20260428-001.json
  ```

**Actual Stdout Output:**

```text
[2026-04-28T12:00:00Z] PHISHING TRIAGE PLAYBOOK
Alert      : ALT-20260428-001
Rule       : phishing_email_suspicious_sender
IOCs       : 3 extracted, 2 enriched
  198.51.100.42          ipv4    BLOCK       score=95  (c2, cobalt_strike)
  meddefense-secure.net  domain  BLOCK       score=97  (typosquat, phishing)
  198.51.100.42          [dedup, skipped]
Verdict    : ESCALATE
Case       : CASE-20260428-001  Severity: Critical  Status: escalated
Action     : SOC notification queued for on-call analyst
```

**Case Created (cases.db verification via case_manager.py get CASE-20260428-001):**

```
Case ID: CASE-20260428-001
Severity: Critical
Status: escalated
IOCs Linked: 198.51.100.42 (BLOCK), meddefense-secure.net (BLOCK)
```

**Expected vs Actual Verdict:** PASS

---

### Test 2: ALT-20260428-002 (Phishing Triage - Unknown External Sender)
* **Scenario:** Phishing email with an unknown external sender IP and domain not present in the threat intel feed.
* **Command Executed:**
  ```bash
  python3 playbook_phishing_triage.py alerts/phishing/ALT-20260428-002.json
  ```

**Actual Stdout Output:**

```text
[2026-04-28T12:01:15Z] PHISHING TRIAGE PLAYBOOK
Alert      : ALT-20260428-002
Rule       : phishing_email_external_sender
IOCs       : 2 extracted, 2 enriched
  203.0.113.99           ipv4    INVESTIGATE score=30  
  external-domain.com    domain  INVESTIGATE score=30  
Verdict    : REVIEW
Case       : CASE-20260428-002  Severity: High  Status: open
Action     : Queued for manual analyst review
```

**Case Created (cases.db verification):**

```
Case ID: CASE-20260428-002
Severity: High
Status: open
```

**Expected vs Actual Verdict:** PASS

---

### Test 3: ALT-20260428-003 (Phishing Triage - Internal Sender)
* **Scenario:** Internal phishing alert originating from a private IP address range (192.168.x.x).
* **Command Executed:**
  ```bash
  python3 playbook_phishing_triage.py alerts/phishing/ALT-20260428-003.json
  ```

**Actual Stdout Output:**

```text
[2026-04-28T12:02:30Z] PHISHING TRIAGE PLAYBOOK
Alert      : ALT-20260428-003
Rule       : phishing_email_internal_relay
IOCs       : 2 extracted, 2 enriched
  192.168.1.100          ipv4    ALLOW       score=0   
  internal.meddefense.local domain ALLOW      score=0   
Verdict    : CLOSE
Case       : CASE-20260428-003  Severity: Low  Status: closed
Action     : Auto-closed: No indicators of compromise
```

**Case Created (cases.db verification):**

```
Case ID: CASE-20260428-003
Severity: Low
Status: closed (Resolution: no_indicators_of_compromise)
```

**Expected vs Actual Verdict:** PASS

---

### Test 4: ALT-20260428-007 (Credential Exposure - LSASS Dump by Domain Admin)
* **Scenario:** LSASS memory dump (T1003.001) executed on workstation WST-WS-031 from a known malicious C2 IP (198.51.100.42) using Domain Admin account svc_helpdesk.
* **Command Executed:**
  ```bash
  python3 playbook_credential_exposure.py alerts/credential/ALT-20260428-007.json
  ```

**Actual Stdout Output:**

```text
[2026-04-28T12:05:00Z] CREDENTIAL EXPOSURE PLAYBOOK
Alert      : ALT-20260428-007
Rule       : credential_access_lsass_dump
Host       : WST-WS-031
User       : svc_helpdesk (Domain Admin: True, Server Admin: True)
Technique  : T1003.001 - LSASS Memory
Source IP  : 198.51.100.42    verdict=BLOCK score=95
Verdict    : ESCALATE
Case       : CASE-20260428-004  Severity: Critical  Status: escalated
Action     : Host flagged and queued for analyst-authorized EDR isolation
```

**Case Created & Isolation Queue Verification:**

```
Case ID: CASE-20260428-004
Severity: Critical
Status: escalated
Host Queued: WST-WS-031 added to isolation_queue.json with status pending_authorization.
```

**Expected vs Actual Verdict:** PASS

---

### Test 5: ALT-20260428-009 (Credential Exposure - Pass the Hash by Standard User)
* **Scenario:** Pass the Hash lateral movement (T1550.002) from an internal IP address by a standard user account.
* **Command Executed:**
  ```bash
  python3 playbook_credential_exposure.py alerts/credential/ALT-20260428-009.json
  ```

**Actual Stdout Output:**

```text
[2026-04-28T12:06:15Z] CREDENTIAL EXPOSURE PLAYBOOK
Alert      : ALT-20260428-009
Rule       : lateral_movement_pth
Host       : WST-SRV-012
User       : jdoe (Domain Admin: False, Server Admin: False)
Technique  : T1550.002 - Pass the Hash
Source IP  : 10.100.45.22     verdict=ALLOW score=0
Verdict    : REVIEW
Case       : CASE-20260428-005  Severity: Medium  Status: open
Action     : Queued for standard review
```

**Case Created & Isolation Queue Verification:**

```
Case ID: CASE-20260428-005
Severity: Medium
Status: open
Isolation Queue: No entry appended (correctly respects safety governance requiring human override/escalation).
```

**Expected vs Actual Verdict:** PASS

---

## Post-Test System State Verification

### 1. Case Manager Summary (`python3 case_manager.py list`)

```text
+---------------------+---------------------+----------+----------------------------------------+---------+
| Case ID             | Alert ID            | Severity | Title                                  | Status  |
+---------------------+---------------------+----------+----------------------------------------+---------+
| CASE-20260428-005   | ALT-20260428-009    | Medium   | Credential Access: Lateral Movement... | open    |
| CASE-20260428-004   | ALT-20260428-007    | Critical | Credential Access: Lsass Dump on WS... | escalated|
| CASE-20260428-003   | ALT-20260428-003    | Low      | Phishing: Phishing Email Internal R... | closed  |
| CASE-20260428-002   | ALT-20260428-002    | High     | Phishing: Phishing Email External S... | open    |
| CASE-20260428-001   | ALT-20260428-001    | Critical | Phishing: Phishing Email Suspicious... | escalated|
+---------------------+---------------------+----------+----------------------------------------+---------+
5 cases (all cases)
```

### 2. Isolation Queue State (`cat isolation_queue.json`)

```json
[
  {
    "queued_at": "2026-04-28T12:05:00Z",
    "host": "WST-WS-031",
    "alert_id": "ALT-20260428-007",
    "case_id": "CASE-20260428-004",
    "reason": "LSASS Memory (T1003.001) from IP 198.51.100.42 (verdict: BLOCK) by user svc_helpdesk (DA: True)",
    "action_required": "Analyst must authorize isolation via EDR console before execution",
    "status": "pending_authorization"
  }
]
```
```
