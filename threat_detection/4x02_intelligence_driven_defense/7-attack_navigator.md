# MITRE ATT&CK Mapping & Navigator Layer: HEALTHBANE Campaign

## 1. Summary Statistics & Overview

| Metric | Value |
|--------|-------|
| **Total techniques identified** | 12 |
| **Observed vs. Inferred ratio** | 7 Observed (58.3%) / 5 Inferred (41.7%) |
| **Tactics with most coverage** | Initial Access (3 techniques), Credential Access (3 techniques), Execution (2 techniques) |
| **Tactics with least coverage** | Defense Evasion (1 technique), Command and Control (2 techniques), Exfiltration (1 technique) |

### Most Important Techniques for Detection Planning

| Technique | ID | Rationale |
|-----------|----|-----------|
| **Phishing: Spearphishing Link** | T1566.002 | Primary initial vector used across all phishing lures. |
| **User Execution: Malicious File** | T1204.002 | Critical point of failure where users engage with malicious PDF attachments. |
| **Application Layer Protocol: Web Protocols** | T1071.001 | Key egress channel for C2 communications and credential exfiltration. |

---

## 2. Technique Mapping by Tactic

### Initial Access

#### T1566.001 — Phishing: Spearphishing Attachment

| Field | Details |
|-------|---------|
| **Classification** | OBSERVED |
| **Evidence** | Delivery of malicious PDF invoices (`phishing_sample.pdf`, `healthbane_lure_02.pdf`) via email. |
| **Source** | Internal Investigation & Researcher Blog |
| **Attack Phase** | Stage 1 / Stage 2 |

#### T1566.002 — Phishing: Spearphishing Link

| Field | Details |
|-------|---------|
| **Classification** | OBSERVED |
| **Evidence** | Phishing emails containing links to fraudulent login portals (`meddefense-portal.com`, `medequip-supplies.net`). |
| **Source** | Internal Investigation & HC3 Advisory |
| **Attack Phase** | Stage 1 |

#### T1192 — Phishing (Legacy / General Campaign Indicator)

| Field | Details |
|-------|---------|
| **Classification** | INFERRED |
| **Evidence** | Broader sector-wide campaign patterns noted in commercial feeds suggesting automated mass-phishing distribution. |
| **Source** | Commercial Threat Feed |
| **Attack Phase** | Stage 1 |

---

### Execution

#### T1204.002 — User Execution: Malicious File

| Field | Details |
|-------|---------|
| **Classification** | OBSERVED |
| **Evidence** | Users opening PDF attachments and clicking embedded URI links pointing to credential harvesting sites. |
| **Source** | Internal Investigation & HC3 Advisory |
| **Attack Phase** | Stage 2 |

#### T1059.003 — Command and Scripting Interpreter: Windows Command Shell

| Field | Details |
|-------|---------|
| **Classification** | INFERRED |
| **Evidence** | Inferred execution of secondary helper scripts following initial document engagement. |
| **Source** | Researcher Blog Analysis |
| **Attack Phase** | Stage 2 |

---

### Credential Access

#### T1566 — Phishing for Credentials

| Field | Details |
|-------|---------|
| **Classification** | OBSERVED |
| **Evidence** | Fake login portals designed to harvest employee username and password credentials (`dmarsh`, `arivera`, etc.). |
| **Source** | Internal Investigation & HC3 Advisory |
| **Attack Phase** | Stage 1 |

#### T1588.002 — Obtain Capabilities: Tool

| Field | Details |
|-------|---------|
| **Classification** | INFERRED |
| **Evidence** | Acquisition of credential harvesting frameworks and pre-built PDF templates. |
| **Source** | HC3 Advisory |
| **Attack Phase** | Stage 1 |

#### T1539 — Steal Web Session Cookie

| Field | Details |
|-------|---------|
| **Classification** | INFERRED |
| **Evidence** | Potential follow-up token hijacking following successful credential capture on fake SSO portals. |
| **Source** | Internal Investigation |
| **Attack Phase** | Stage 1 / 2 |

---

### Defense Evasion

#### T1027 — Obfuscated Files or Information

| Field | Details |
|-------|---------|
| **Classification** | OBSERVED |
| **Evidence** | Use of encoded URI actions and obfuscated redirect links within PDF object streams (`/Annots`). |
| **Source** | Researcher Blog Analysis |
| **Attack Phase** | Stage 2 |

---

### Command and Control

#### T1071.001 — Application Layer Protocol: Web Protocols

| Field | Details |
|-------|---------|
| **Classification** | OBSERVED |
| **Evidence** | HTTPS beaconing to C2 infrastructure (`healthbane-c2.net`) and external VPS nodes. |
| **Source** | HC3 Advisory & Internal Investigation |
| **Attack Phase** | Stage 2 / 3 |

#### T1573.001 — Encrypted Channel: Symmetric Cryptography

| Field | Details |
|-------|---------|
| **Classification** | INFERRED |
| **Evidence** | Standard TLS encryption utilized across outbound C2 and exfiltration channels to blend with normal web traffic. |
| **Source** | Researcher Blog Analysis |
| **Attack Phase** | Stage 3 |

---

### Exfiltration

#### T1041 — Exfiltration Over C2 Channel

| Field | Details |
|-------|---------|
| **Classification** | OBSERVED |
| **Evidence** | Outbound transmission of harvested credentials, billing records, and administrative data over established C2 web channels. |
| **Source** | Internal Investigation & HC3 Advisory |
| **Attack Phase** | Stage 3 |

---
