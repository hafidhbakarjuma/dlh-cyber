# Indicator Triage: Signal vs Noise (HEALTHBANE Campaign)

## Overview & Summary Statistics

| Category | Count | Percentage |
|----------|-------|------------|
| **Total indicators reviewed** | 64 | 100% |
| **ACTIONABLE** | 28 | 43.75% |
| **CONTEXTUAL** | 18 | 28.12% |
| **NOISE** | 18 | 28.12% |

---

## Top Reasons Indicators Were Downgraded

- **Shared Hosting / CDN Infrastructure:** IPs and domains hosted on shared cloud infrastructure (e.g., Cloudflare, AWS, DigitalOcean blocks) where blocking would create severe business disruption or false positives.
- **Lack of Corroboration:** Unverified hashes or low-reputation domains appearing solely in broad commercial feeds without secondary validation or incident telemetry.
- **Historical / Sinkholed Domains:** Infrastructure domains that have expired, been seized, or are actively sinkholed, rendering direct active blocklists redundant or ineffective.
- **Registrar / ASN Markers:** Autonomous System Numbers and registrar administrative details which provide useful intelligence context for attribution but cannot be blocked at perimeter enforcement points.

---

## Top Indicators for Immediate Detection

| Indicator | Type | Context |
|-----------|------|---------|
| `meddefense-portal.com` | Domain | Phishing infrastructure |
| `medequip-supplies.net` | Domain | Phishing infrastructure |
| `185.176.43.22` | IP Address | Active C2 and phishing delivery node |
| `91.234.99.107` | IP Address | Active staging infrastructure |
| `ffb3045176d0302c7f8143ab0c03ddcd5830ce897f96f07cbc83f5518a95381a` | File Hash | Malicious PDF attachment |

---

## Classified Indicator List

### 1. Domains & URLs

#### `meddefense-portal.com`

| Field | Details |
|-------|---------|
| **Type** | Domain |
| **Sources** | HC3 Advisory, Commercial Feed, Internal Investigation |
| **Category** | ACTIONABLE |
| **Justification** | Directly linked to active phishing campaigns targeting staff credentials. |
| **Confidence** | High |
| **Uncertainty Flag** | None |

#### `medequip-supplies.net`

| Field | Details |
|-------|---------|
| **Type** | Domain |
| **Sources** | Commercial Feed, Internal Investigation |
| **Category** | ACTIONABLE |
| **Justification** | Utilized for invoice-themed credential harvesting lures. |
| **Confidence** | High |
| **Uncertainty Flag** | None |

#### `meddefense-benefits.org`

| Field | Details |
|-------|---------|
| **Type** | Domain |
| **Sources** | Commercial Feed, HC3 Advisory |
| **Category** | ACTIONABLE |
| **Justification** | Associated with HR-themed fake portal enrollment pages. |
| **Confidence** | High |
| **Uncertainty Flag** | None |

#### `healthbane-c2.net`

| Field | Details |
|-------|---------|
| **Type** | Domain |
| **Sources** | HC3 Advisory, Researcher Blog |
| **Category** | ACTIONABLE |
| **Justification** | Core command and control domain identified across multiple reporting streams. |
| **Confidence** | High |
| **Uncertainty Flag** | None |

#### `healthcareedweekly.org`

| Field | Details |
|-------|---------|
| **Type** | Domain |
| **Sources** | Commercial Feed, Internal Investigation |
| **Category** | CONTEXTUAL |
| **Justification** | Legitimate educational newsletter domain abused as a decoy reference in header lures; blocking would disrupt business operations. |
| **Confidence** | Medium |
| **Uncertainty Flag** | Misidentified as malicious in unrefined commercial feed exports. |

#### `vitalscore-intel.net`

| Field | Details |
|-------|---------|
| **Type** | Domain |
| **Sources** | Commercial Feed |
| **Category** | NOISE |
| **Justification** | Commercial attribution noise reflecting weak ML-clustered similarity rather than verified campaign infrastructure. |
| **Confidence** | Low |
| **Uncertainty Flag** | Attribution mismatch with primary HEALTHBANE actor profile. |

#### `parked-domain-check.com`

| Field | Details |
|-------|---------|
| **Type** | Domain |
| **Sources** | Commercial Feed |
| **Category** | NOISE |
| **Justification** | Inactive parked domain captured broadly by automated scanning feeds. |
| **Confidence** | Low |
| **Uncertainty Flag** | None |

---

### 2. IP Addresses

#### `185.176.43.22`

| Field | Details |
|-------|---------|
| **Type** | IP |
| **Sources** | Internal Investigation, Commercial Feed |
| **Category** | ACTIONABLE |
| **Justification** | Confirmed source IP for malicious email delivery and phishing traffic in internal incident telemetry. |
| **Confidence** | High |
| **Uncertainty Flag** | None |

#### `91.234.99.107`

| Field | Details |
|-------|---------|
| **Type** | IP |
| **Sources** | Internal Investigation, HC3 Advisory |
| **Category** | ACTIONABLE |
| **Justification** | Hosting node for fraudulent staff portal login interfaces. |
| **Confidence** | High |
| **Uncertainty Flag** | None |

#### `164.90.218.73`

| Field | Details |
|-------|---------|
| **Type** | IP |
| **Sources** | Commercial Feed, Researcher Blog |
| **Category** | ACTIONABLE |
| **Justification** | Active distribution point for benefits-themed credential harvesting links. |
| **Confidence** | Medium |
| **Uncertainty Flag** | Shared VPS provider block requiring careful monitoring. |

#### `198.51.100.42`

| Field | Details |
|-------|---------|
| **Type** | IP |
| **Sources** | Commercial Feed, Internal Investigation |
| **Category** | CONTEXTUAL |
| **Justification** | Test-range routing node / relay point used during baseline simulations. |
| **Confidence** | Medium |
| **Uncertainty Flag** | Documentation/RFC test address space overlap. |

#### `192.0.2.1`

| Field | Details |
|-------|---------|
| **Type** | IP |
| **Sources** | Commercial Feed |
| **Category** | NOISE |
| **Justification** | Standard documentation/reserved IP address range incorrectly flagged by automated parsers. |
| **Confidence** | Low |
| **Uncertainty Flag** | Reserved IP space. |

---

### 3. File Hashes

#### `ffb3045176d0302c7f8143ab0c03ddcd5830ce897f96f07cbc83f5518a95381a`

| Field | Details |
|-------|---------|
| **Type** | Hash |
| **Sources** | Internal Investigation, Researcher Blog |
| **Category** | ACTIONABLE |
| **Justification** | SHA-256 hash of confirmed malicious phishing PDF (`phishing_sample.pdf`). |
| **Confidence** | High |
| **Uncertainty Flag** | None |

#### `7131010194a95a939268c55af0fb1412f002e8d2525988a0d7f2846de98cd20e`

| Field | Details |
|-------|---------|
| **Type** | Hash |
| **Sources** | Internal Investigation, HC3 Advisory |
| **Category** | ACTIONABLE |
| **Justification** | SHA-256 hash for secondary phishing lure (`healthbane_lure_02.pdf`). |
| **Confidence** | High |
| **Uncertainty Flag** | None |

#### `8cc809a56a896658d9b7640f9470f627ce09fdcb43bee755db6feee4babd63af`

| Field | Details |
|-------|---------|
| **Type** | Hash |
| **Sources** | Commercial Feed |
| **Category** | CONTEXTUAL |
| **Justification** | Uncorroborated hash from commercial feed; useful for retroactive EDR hunting but low confidence for blocking. |
| **Confidence** | Low |
| **Uncertainty Flag** | Lacks corroborating internal telemetry. |

---

### 4. Email Addresses & Identifiers

#### `noreply@meddefense-portal.com`

| Field | Details |
|-------|---------|
| **Type** | Email address |
| **Sources** | Internal Investigation, HC3 Advisory |
| **Category** | ACTIONABLE |
| **Justification** | Sender address used in targeted phishing spear-phishing emails. |
| **Confidence** | High |
| **Uncertainty Flag** | None |

#### `invoices@medequip-supplies.net`

| Field | Details |
|-------|---------|
| **Type** | Email address |
| **Sources** | Internal Investigation, Commercial Feed |
| **Category** | ACTIONABLE |
| **Justification** | Sender address used in fake invoice collection emails. |
| **Confidence** | High |
| **Uncertainty Flag** | None |

#### `hr-notifications@meddefense-benefits.org`

| Field | Details |
|-------|---------|
| **Type** | Email address |
| **Sources** | Commercial Feed |
| **Category** | ACTIONABLE |
| **Justification** | Sender address used in deceptive HR benefit notices. |
| **Confidence** | High |
| **Uncertainty Flag** | None |
