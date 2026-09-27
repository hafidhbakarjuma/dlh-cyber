# HEALTHBANE Campaign: Comprehensive Intelligence Brief & Executive Report

**Target Audience:** Dr. Morales, MedDefense Board of Directors, and Healthcare-Sector Partners
**Classification:** TLP:CLEAR / Operational Intelligence Brief
**Author:** Cyber Threat Intelligence & Defense Team (dlh-cyber_security)

---

## 1. Executive Summary

HEALTHBANE is a sophisticated multi-stage cyber campaign specifically targeting healthcare providers through spear-phishing, credential harvesting, malware delivery, and encrypted data exfiltration. At MedDefense, the campaign manifested as targeted spear-phishing emails containing malicious PDF attachments and credential-harvesting portal links directed at administrative and clinical personnel. Across the broader healthcare sector, similar organizations experienced unauthorized credential access and staging vector deployments leading to potential data compromise.

Our current detection posture successfully covers mail gateway file scanning and known static domain/IP indicators, but contains notable blind spots regarding encrypted command-and-control (C2) traffic and unmonitored script execution. To secure our enterprise, we recommend three immediate actions:

1. Deploying phishing-resistant FIDO2 multi-factor authentication across all staff accounts.
2. Implementing endpoint detection rules to monitor PDF reader process executions and network calls.
3. Operationalizing our validated YARA rules across all email and endpoint defenses.

---

## 2. Adversary Profile

The adversary orchestrating the HEALTHBANE campaign exhibits high operational capability, stealth-oriented infrastructure management, and specialized knowledge of healthcare administrative workflows. While commercial threat feeds label the actor cluster as **VITALSCORE** and independent researchers designate them as **APT-MEDAGENT**, government and internal analysis prioritize the campaign identifier **HEALTHBANE** to avoid automated ML-clustering bias.

The group utilizes ephemeral virtual private servers (VPS), shared hosting providers (e.g., Cloudflare/CDN hiding layers), and custom-generated PDF lure documents to blend into standard corporate communications. Their primary motivation is financial and intellectual property theft, specifically targeting billing records, patient administration databases, and administrative credentials.

---

## 3. Campaign Analysis

The HEALTHBANE campaign follows a disciplined three-stage kill chain:

### Stage 1: Credential Harvesting (Early to Mid-April 2026)

| Field | Details |
|-------|---------|
| **Operation** | Multi-pronged spear-phishing emails utilizing spoofed sender domains (`meddefense-portal.com`, `medequip-supplies.net`) targeting administrative and HR staff. |
| **Evidence Confidence** | High (Confirmed via raw `.eml` headers and internal mail gateway telemetry). |

### Stage 2: Malware Delivery & Staging (Mid-April 2026)

| Field | Details |
|-------|---------|
| **Operation** | Distribution of malicious PDF invoice and portal lures (`phishing_sample.pdf`, `healthbane_lure_02.pdf`) containing embedded URI redirect annotations generated via `wkhtmltopdf 0.12.6`. |
| **Evidence Confidence** | High (Confirmed via file hashes and reverse-engineering analysis). |

### Stage 3: Data Exfiltration & C2 (Mid-to-Late April 2026)

| Field | Details |
|-------|---------|
| **Operation** | Outbound HTTPS beaconing to C2 infrastructure (`healthbane-c2.net`) and transmission of harvested credentials and billing data. |
| **Evidence Confidence** | Medium (Corroborated by network anomaly spikes and commercial threat feed correlations). |

### Campaign Timeline

| Date | Event |
|------|-------|
| Early April 2026 | Earliest known reconnaissance and domain registration. |
| April 14, 2026 | MedDefense Stage 1 spear-phishing event and publication of HC3 sector advisory. |
| Mid-April 2026 | Secondary malware delivery and staging attempts. |
| April 15, 2026 | Independent open-source researcher blog analysis published. |

---

## 4. ATT&CK Mapping

Our analysis distinguishes between **OBSERVED** techniques (confirmed via direct internal logs and sample artifacts) and **INFERRED** techniques (derived from campaign behavior and intelligence extrapolation):

| ATT&CK ID | Technique Name | Classification | Tactic | Detection Relevance |
|-----------|----------------|----------------|--------|---------------------|
| T1566.001 | Spearphishing Attachment | OBSERVED | Initial Access | Critical mail gateway filtering point |
| T1566.002 | Spearphishing Link | OBSERVED | Initial Access | Essential DNS / proxy blocking target |
| T1192 | Phishing (General) | INFERRED | Initial Access | Broad campaign tracking metric |
| T1204.002 | User Execution: Malicious File | OBSERVED | Execution | Endpoint monitoring for PDF interactions |
| T1059.003 | Windows Command Shell | INFERRED | Execution | Post-lure script execution monitoring |
| T1566 | Phishing for Credentials | OBSERVED | Credential Access | SSO authentication log anomaly tracking |
| T1588.002 | Obtain Capabilities: Tool | INFERRED | Credential Access | External threat intelligence scoping |
| T1539 | Steal Web Session Cookie | INFERRED | Credential Access | Conditional access and token validation |
| T1027 | Obfuscated Files or Information | OBSERVED | Defense Evasion | Static YARA and binary inspection |
| T1071.001 | Web Protocols (HTTPS C2) | OBSERVED | Command & Control | Network traffic analysis and JA3 fingerprinting |
| T1573.001 | Encrypted Channel | INFERRED | Command & Control | TLS inspection and egress policy tuning |
| T1041 | Exfiltration Over C2 Channel | OBSERVED | Exfiltration | DLP anomaly and data volume monitoring |

---

## 5. Detection Gap Assessment

Prioritized gaps identified by comparing our ATT&CK mapping against current telemetry:

### Priority 1 (Observed & Not Detected)

**T1059.003 (Command & Scripting Interpreter):** Lacks automated command-line auditing on user workstations, creating a blind spot for secondary script execution.
- **Recommendation:** Enable Windows Event ID 4688 with full command-line argument auditing.

### Priority 1 (Inferred & Not Detected)

**T1539 (Steal Web Session Cookie):** Insufficient continuous session validation allows hijacked tokens to bypass standard MFA.
- **Recommendation:** Implement strict conditional access device binding.

### Priority 2 (Inferred & Not Detected)

**T1573.001 (Encrypted Channel):** Enterprise privacy policies exempt medical traffic from TLS decryption, blinding defenders to C2 payloads.
- **Recommendation:** Deploy JA3/JA4 TLS fingerprinting on network boundaries.

### Priority 3 (Partially Detected)

**T1204.002 (User Execution):** Document viewers spawn processes without direct correlation to outbound browser requests.
- **Recommendation:** Deploy EDR rules alerting when document viewers initiate external network calls.

---

## 6. Indicator of Compromise (IOC) Table

| Indicator Type | Indicator Value | Attack Phase | Confidence | Recommended Action |
|----------------|-----------------|--------------|------------|---------------------|
| Domain | `meddefense-portal.com` | Stage 1 (Phishing) | High | BLOCK at web proxy & DNS |
| Domain | `medequip-supplies.net` | Stage 1 (Phishing) | High | BLOCK at web proxy & DNS |
| Domain | `meddefense-benefits.org` | Stage 1 (Phishing) | High | BLOCK at web proxy & DNS |
| Domain | `healthbane-c2.net` | Stage 2/3 (C2) | High | BLOCK & monitor egress traffic |
| IP Address | `185.176.43.22` | Stage 1 (Delivery) | High | BLOCK firewall / NetFlow drop |
| IP Address | `91.234.99.107` | Stage 2 (Staging) | High | BLOCK firewall / NetFlow drop |
| File Hash (SHA-256) | `ffb3045176d0302c7f8143ab0c03ddcd5830ce897f96f07cbc83f5518a95381a` | Stage 2 (PDF Lure) | High | QUARANTINE via EDR/AV |
| File Hash (SHA-256) | `7131010194a95a939268c55af0fb1412f002e8d2525988a0d7f2846de98cd20e` | Stage 2 (PDF Lure) | High | QUARANTINE via EDR/AV |

---

## 7. YARA Rule Summary

| Field | Details |
|-------|---------|
| **Rules Developed** | `9-yara_phishing_pdf.yar` (Detects malicious wkhtmltopdf-generated PDF lure structures and harvesting URIs). `10-yara_arsenal.yar` (Detects campaign email headers and composite indicators). |
| **Test Results** | Tested against the local corpus (`samples/`) yielding 100% Detection Rate, 0% False Positive Rate, and 100% Precision across true positives (`phishing_sample.pdf`, `healthbane_lure_02.pdf`) and true negatives (`clean_invoice.pdf`, `benign_invoice.pdf`). |
| **Deployment Status** | **DEPLOY** (Cleared for automated production SIEM and endpoint EDR enforcement). |

---

## 8. Strategic Recommendations

### Immediate (48 Hours)

- Block all verified IOC domains and IP addresses across perimeter firewalls and DNS sinks.
- Force credential resets and session invalidations for all targeted user accounts (`dmarsh`, `arivera`, etc.).
- Deploy and activate YARA rules (`9-yara_phishing_pdf.yar` and `10-yara_arsenal.yar`) across mail and endpoint gateways.

### Short-Term (2 Weeks)

- Implement phishing-resistant FIDO2 multi-factor authentication (MFA) across all employee accounts.
- Enable Windows Event ID 4688 command-line auditing on all workstations to close T1059.003 visibility gaps.
- Conduct mandatory targeted phishing awareness refresher training for billing and HR personnel.

### Medium-Term (30 Days)

- Deploy Network Traffic Analysis (NTA) tools featuring JA3/JA4 SSL client fingerprinting to detect encrypted C2 beaconing.
- Establish automated threat-intelligence sharing protocols with healthcare ISAC partners and HC3 advisory feeds.
- Conduct a comprehensive red-team simulation modeling the HEALTHBANE spear-phishing attack chain.

---

## 9. Intelligence Gaps & Collection Priorities

| Question | Answer |
|----------|--------|
| **What Remains Unknown** | Complete visibility into secondary payload downloads performed by external victims outside MedDefense visibility, and the precise geopolitical/financial identity behind the adversary. |
| **What Collection Would Answer It** | Expanded telemetry sharing across sector ISAC partners, deeper memory forensics on isolated compromise endpoints, and coordinated law enforcement traceback. |
| **Who Should Be Asked / Data Reviewed** | Request sector-wide incident summaries from HHS HC3 and Healthcare ISAC; review internal proxy logs and endpoint EDR historical telemetry for anomalous URI interactions. |
