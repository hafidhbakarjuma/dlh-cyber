# 4x00 — Phishing Dissection & Incident Response

*Email forensics, social engineering analysis, IOC extraction and campaign correlation for MedDefense Health Systems*

![Track](https://img.shields.io/badge/Track-SOC%20Analyst%20%2F%20Email%20Forensics-blue)
![Framework](https://img.shields.io/badge/Framework-MITRE%20ATT%26CK%20T1566-red)
![Intel](https://img.shields.io/badge/Intel-HHS%20HC3-green)
![Method](https://img.shields.io/badge/Method-Defanged%20%7C%20No%20Live%20Execution-orange)
![Status](https://img.shields.io/badge/Status-Complete-brightgreen)

> *"The attacker doesn't hack the firewall. The attacker sends an email."* — adapted from Kevin Mitnick

**Program:** DLH Cybersecurity Academy — SOC Analyst / Penetration Testing track
**Author:** [hafidhbakarjuma](https://github.com/hafidhbakarjuma)
**Module position:** First project of Module 4. Its indicators feed 4x01, 4x02 and 4x05.

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Scenario](#scenario)
3. [Learning Objectives](#learning-objectives)
4. [Key Findings](#key-findings)
5. [Repository Structure](#repository-structure)
6. [Deliverables Index](#deliverables-index)
7. [Methodology and Safety Rules](#methodology-and-safety-rules)
8. [Conceptual Review Questions](#conceptual-review-questions)
9. [Skills Demonstrated](#skills-demonstrated)
10. [Project Series](#project-series)
11. [References](#references)

---

## Executive Summary

Phishing is the dominant initial access vector in healthcare. The 2025 Verizon DBIR attributes over 40% of initial access to phishing and pretexting across industries, and 56% in healthcare.

This project is a complete investigation of **8 raw emails** received by MedDefense Health Systems between **April 14 and April 16, 2026**. The work covers triage, SMTP header analysis, SPF/DKIM/DMARC interpretation, social engineering profiling, safe URL and attachment autopsy, a user click assessment, campaign correlation against an HHS HC3 alert, IOC extraction and a formal investigation report.

**Outcome:** 4 of 8 emails were malicious (3 targeted phishing, 1 opportunistic), 1 was spam and 3 were legitimate. Emails E2, E5 and E7 were assessed as one coordinated campaign.

---

## Scenario

Week eleven at MedDefense. Over 72 hours the helpdesk received 6 reports of suspicious email across three departments, and the mail gateway quarantined 2 more. Staff reported an unexplained billing email, an invoice that looked wrong, and a nurse who clicked a "portal verification" link. HC3 was tracking a regional credential-harvesting campaign using lookalike domains, with no published IOCs yet, so MedDefense could be the first organization to report them.

**Three priorities set by the security director:**

1. Analyze every email and separate threats from noise.
2. Determine whether the malicious emails are connected.
3. Determine whether the nurse's credentials were compromised.

---

## Learning Objectives

By the end of this project, you are expected to be able to explain to anyone, without the help of Google:

### Email Security Architecture
- How SMTP headers record the routing path of an email from sender to recipient
- How SPF validates sender IP authorization and what each result (pass, fail, softfail, none) means
- How DKIM provides cryptographic message integrity and what a valid signature proves (and does not prove)
- How DMARC ties SPF and DKIM to the visible From domain and enforces organizational policy
- Why an email can pass all authentication checks and still be malicious

### Threat Investigation Methodology
- How to safely investigate suspicious URLs without navigating to them directly
- How to analyze email attachments without executing them
- How to identify social engineering techniques in email content (urgency, authority, fear, impersonation)
- How to distinguish a coordinated campaign from unrelated phishing attempts using infrastructure analysis
- How to correlate multiple phishing emails using shared infrastructure, domains and indicators

### Evidence-Based Analysis
- How to extract, categorize and structure indicators of compromise from investigation artifacts
- How to assess IOC quality (strong vs. weak indicators, confidence levels, false positive potential)
- How to produce professional investigation reports that support downstream decisions
- How to translate investigation findings into new detection rules

---

## Key Findings

### Final verdicts

| Email | Sender domain | Final class | Confidence |
|-------|---------------|-------------|------------|
| E1 | `healthcare-education-weekly[.]com` | LEGITIMATE | HIGH |
| E2 | `meddefense-portal[.]com` | PHISHING-TARGETED | HIGH |
| E3 | `outlook-protection[.]com` | PHISHING-OPPORTUNISTIC | HIGH |
| E4 | `meddefense[.]com` (internal) | LEGITIMATE | HIGH |
| E5 | `medequip-supplies[.]net` | PHISHING-TARGETED | HIGH |
| E6 | `canadian-pharma-discount[.]org` | SPAM | HIGH |
| E7 | `meddefense-benefits[.]org` | PHISHING-TARGETED | HIGH |
| E8 | `hhs[.]gov` (HC3 alert) | LEGITIMATE | HIGH |

**Triage accuracy:** 7 of 8 initial classifications matched the final verdict. E3 was refined from generic "suspicious" to opportunistic brand impersonation.

### Campaign: E2, E5, E7

| Dimension | Evidence |
|-----------|----------|
| Tooling | All three sent with `PHPMailer 6.6.0` |
| Infrastructure | Unauthenticated external VPS hosts; SPF fail/softfail, DKIM none, DMARC fail |
| Pretext | Hard deadlines: 24-hour re-verification, 7-day payment, "closes tomorrow" |
| Targeting | E2 clinical staff, E5 accounts payable, E7 HR / benefits |
| Timing | E2 April 14 (14:47 CDT); E5 and E7 April 16 (11:28 and 15:22 CDT) |
| Sector match | Aligns with the HC3 alert: new lookalike domains with "portal", "supplies", "benefits" |

**Attribution:** A single actor or shared phishing kit is inferred. Attribution to a named group is **not** provable from headers and basic OSINT.

### The E3 lesson: authentication is not trust
E3 passed SPF, DKIM and DMARC. Those results only prove the sender controls `outlook-protection[.]com`. They say nothing about whether that domain belongs to Microsoft, and it does not.

### Click incident
A nurse clicked the E2 link from `WS-NURSE-04` on April 14 at 15:02:33 CDT, about 15 minutes after delivery. The evidence **confirms the click** but **cannot confirm credential entry**, token theft or endpoint execution. The report therefore treats it as a potential exposure and recommends password reset, session revocation and a user interview.

---

## Repository Structure

```text
4x00_phishing_dissection/
├── README.md
├── 0-initial_triage.md
├── 1-header_analysis.md
├── 2-authentication_analysis.md
├── 3-social_engineering.md
├── 4-url_attachment_autopsy.md
├── 7-click_investigation.md
├── 8-verdict_matrix.md
├── 9-campaign_thread.md
├── 11-ioc_extraction.md
└── 13-phishing_investigation_report.md
```

---

## Deliverables Index

| # | File | Focus |
|---|------|-------|
| 0 | [`0-initial_triage.md`](0-initial_triage.md) | First-pass triage table: auth results, class and priority for E1–E8 |
| 1 | [`1-header_analysis.md`](1-header_analysis.md) | SMTP header deep-dive of E2, E3, E5, E7: Received chains, sending IPs, X-Mailer, anomalies |
| 2 | [`2-authentication_analysis.md`](2-authentication_analysis.md) | SPF, DKIM and DMARC interpretation for all 8 emails, including the auth-passing lookalike (E3) |
| 3 | [`3-social_engineering.md`](3-social_engineering.md) | Psychological lever, pretext, requested action, targeting level and red flags |
| 4 | [`4-url_attachment_autopsy.md`](4-url_attachment_autopsy.md) | Defanged URLs, domain/IP extraction, safe lookup commands, attachment indicators |
| 7 | [`7-click_investigation.md`](7-click_investigation.md) | Confirmed facts vs. unknowns, endpoint and identity checks, decision matrix, containment |
| 8 | [`8-verdict_matrix.md`](8-verdict_matrix.md) | Final classification, triage accuracy and actions for all 8 emails |
| 9 | [`9-campaign_thread.md`](9-campaign_thread.md) | E2/E5/E7 correlation by infrastructure, timing and targeting; HC3 comparison; attribution limits |
| 11 | [`11-ioc_extraction.md`](11-ioc_extraction.md) | Structured IOC table by attack phase, quality grading, HC3-ready summary |
| 13 | [`13-phishing_investigation_report.md`](13-phishing_investigation_report.md) | Executive report: timeline, per-email analysis, click assessment, gaps, phased recommendations |

Target indicators covered (defanged): `meddefense-portal[.]com`, `outlook-protection[.]com`, `medequip-supplies[.]net`, `meddefense-benefits[.]org`, `203.0.113[.]228`, and the sending IPs `91.234.99[.]107`, `51.38.42[.]17`, `185.176.43[.]22`.

---

## Methodology and Safety Rules

- **Never navigate directly to suspicious URLs.** Use defanging (`hxxps`, `[.]`), sandboxes and command-line tools.
- **Never open attachments on the analyst workstation.** Use metadata extraction and online sandboxes only.
- **Document everything.** Every conclusion cites specific header, authentication or OSINT evidence.
- **Separate fact from inference.** Confirmed evidence, assessments and unknowns are labeled distinctly.
- **Grade indicator quality.** Lookalike domains are high-confidence blocks; shared hosting providers are monitor-only because blocking them alone risks false positives.
- **No live infrastructure.** No SIEM, Wazuh or Suricata is required; live lookups are optional and methods are documented when they cannot run.

Example safe lookups (run only against defanged, re-fanged-on-purpose values from an isolated lab):

```bash
whois meddefense-portal.com
dig +short meddefense-portal.com
curl -I --max-time 10 https://meddefense-portal.com   # isolated lab only
```

---

## Conceptual Review Questions

### Task 15 — The email authentication paradox
**Question:** An email to the hospital CFO claims to be from "Microsoft 365 Security" and passes SPF, DKIM and DMARC, but the domain is `outlook-protection.com`. Why can it still be malicious?
**Answer:** Authentication proves **infrastructure control**, not **brand ownership**. The checks only confirm the message was authorized and signed for the domain in the header. Attackers register lookalike domains, publish valid records for them and pass gateway filters.

### Task 16 — Safe URL investigation
**Question:** How should an analyst assess `hxxps://portal-update.meddefense-health.com/verify` without visiting it?
**Answer:** (1) Defang and isolate. (2) Deconstruct scheme, subdomain, domain and path. (3) Run passive lookups: `whois`, `dig`, `nslookup`. (4) Query VirusTotal, URLhaus and urlscan.io without rendering the page. (5) Correlate with email logs, SIEM data and asset inventory.

### Task 17 — Campaign identification
**Question:** Three of five emails share same-day domain registration, the same registrar, `PHPMailer 6.6.0`, multi-department targets and the same urgency pattern. Why a campaign and not spam?
**Answer:** Shared tooling, synchronized registration and role-based targeting show centralized provisioning and a deliberate multi-vector strategy that independent spam would not produce.

---

## Skills Demonstrated

**Email security:** SMTP header analysis, SPF / DKIM / DMARC interpretation
**Threat analysis:** social engineering profiling, lookalike domain detection, campaign correlation
**Investigation:** safe URL and attachment handling, click impact assessment, decision matrices
**Intelligence:** IOC extraction and grading, HC3-ready sharing, attribution discipline
**Reporting:** executive summaries, verdict matrices, phased remediation planning

---

## Project Series

| Project | Focus |
|---------|-------|
| **4x00** (this project) | Phishing email investigation and IOC extraction |
| 4x01 | Network forensics from PCAP evidence: what happened after the click |
| 4x02 | Intelligence-driven defense against the HEALTHBANE campaign |
| 4x03 | Malware awareness: static and dynamic analysis of the HEALTHBANE toolchain |
| 4x04 | Threat hunting for Stage 4 living-off-the-land lateral movement |
| 4x05 | Attack reconstruction: cross-evidence correlation and impact assessment |

---

## References

- [RFC 5321: Simple Mail Transfer Protocol](https://www.rfc-editor.org/rfc/rfc5321)
- [DMARC.org overview](https://dmarc.org/overview/)
- [MITRE ATT&CK: Phishing (T1566)](https://attack.mitre.org/techniques/T1566/)
- [HHS HC3 Threat Briefs](https://www.hhs.gov/about/agencies/asa/ocio/hc3/index.html)
- [VirusTotal](https://www.virustotal.com/), [urlscan.io](https://urlscan.io/), [URLhaus](https://urlhaus.abuse.ch/)

---

*Educational project completed as part of the DLH Cybersecurity Academy curriculum. All organizations, personnel and incident details belong to a training scenario.*
