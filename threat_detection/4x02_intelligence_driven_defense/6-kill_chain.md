# HEALTHBANE Campaign: Kill Chain Reconstruction

## 1. Campaign Timeline

| Event | Date | Description |
|-------|------|-------------|
| **Earliest Known Activity** | Early April 2026 | Initial reconnaissance and domain registration for credential harvesting infrastructure. |
| **MedDefense Stage 1 Event** | April 14, 2026 | Spear-phishing emails targeting employee accounts such as `dmarsh@meddefense.com` and `arivera@meddefense.com`. |
| **HC3 Reporting Window** | April 14, 2026 | Publication of sector-wide advisory detailing HEALTHBANE tactics and indicators. |
| **Stage 2 Malware Delivery Window** | Mid-April 2026 | Distribution of malicious PDF attachments containing fake invoice and staff portal action lures. |
| **Stage 3 Exfiltration Window** | Mid-to-late April 2026 | Suspected staging and data exfiltration phase via external C2 channels. |
| **Most Recent Reported Event** | April 15, 2026 | Publication of independent open-source researcher blog analysis providing technical deep-dives into infection vectors. |

---

## 2. Attack Phase Breakdown

### Stage 1: Credential Harvesting

| Field | Details |
|-------|---------|
| **Phishing Operation** | Multi-pronged spear-phishing campaigns utilizing spoofed sender addresses (`noreply@meddefense-portal.com`, `invoices@medequip-supplies.net`, `hr-notifications@meddefense-benefits.org`). |
| **Targeting Pattern** | Healthcare organizations, administrative staff, billing departments, and HR personnel. |
| **Infrastructure Used** | Domains such as `meddefense-portal.com`, `medequip-supplies.net`, and `meddefense-benefits.org` hosted on shared VPS nodes (`185.176.43.22`, `91.234.99.107`, `164.90.218.73`). |
| **Known Victims** | Multiple healthcare entities sector-wide, including specific internal targets at MedDefense. |
| **MedDefense Evidence** | Internal incident logs showing inbound phishing emails with login links and user interaction data. |
| **Success Rate** | Partial credential compromise observed among unauthenticated or rushed staff members prior to mandatory credential resets. |

### Stage 2: Malware Delivery

| Field | Details |
|-------|---------|
| **Transition from Credentials to Follow-up** | Following initial credential capture or direct lure engagement, attackers delivered malicious PDF attachments (`phishing_sample.pdf`, `healthbane_lure_02.pdf`) masquerading as invoices or urgent notices. |
| **Document Type** | PDF documents embedded with malicious hyperlinks (`/Annots`) pointing to external credential harvesting portals and staging servers. |
| **Malware or Script Artifacts** | File hashes `ffb3045176d0302c7f8143ab0c03ddcd5830ce897f96f07cbc83f5518a95381a` and `7131010194a95a939268c55af0fb1412f002e8d2525988a0d7f2846de98cd20e`. |
| **Download Infrastructure** | External hosting nodes associated with commercial CDN blocks and compromised virtual private servers. |
| **Persistence Mechanisms** | Periodic callback requests via embedded URI action handlers and browser redirection. |
| **Evidence Source** | Internal investigation findings, researcher blog reverse-engineering notes, and HC3 advisory IOC lists. |

### Stage 3: Data Exfiltration

| Field | Details |
|-------|---------|
| **Data Targeted** | Patient billing records, administrative credentials, vendor supply chain invoices, and staff directory records. |
| **Protocol or Tool Used** | Encrypted HTTPS connections communicating with C2 domains (`healthbane-c2.net`). |
| **Exfiltration Infrastructure** | External IP addresses and proxy routing nodes designed to obfuscate destination endpoints. |
| **Evidence Source** | Inferred from network telemetry anomaly spikes and commercial feed C2 correlations; direct internal confirmation is limited. |
| **Confirmed vs. Unclear** | Initial staging and C2 beaconing are confirmed by internal telemetry; the exact volume and specific categories of exfiltrated data remain partially unclear due to encryption and limited log retention. |

---

## 3. Evidence Quality Assessment

### Confirmed Evidence

- Initial phishing email headers and raw `.eml` contents (`healthbane_email_01.eml`, `healthbane_email_02.eml`).
- Malicious PDF file structures and embedded URI annotations (`phishing_sample.pdf`, `healthbane_lure_02.pdf`).
- Internal MedDefense endpoint logs showing targeted user accounts (`dmarsh`, `arivera`, `lpatterson`).

### Corroborated Evidence

- Domain infrastructure overlaps between HC3 advisory reports and internal incident discoveries (`meddefense-portal.com`, `medequip-supplies.net`).
- Technical parsing of PDF object streams and lure mechanics reported independently by security researchers.

### Inferred Evidence

- Full scope of external data exfiltration (Stage 3) based on C2 beacon frequency and outbound traffic patterns.
- Broader sector-wide victim impact derived from commercial threat feed intelligence.

### Unknowns

- Exact threat actor identities behind the pseudonymous campaign labels (HEALTHBANE vs. APT-MEDAGENT vs. VITALSCORE).
- Complete inventory of secondary files downloaded by victims who clicked advanced landing pages outside internal network visibility.

---

## 4. Intelligence Gaps & Unknowns

| Gap | Description |
|-----|-------------|
| **Attribution Gaps** | Discrepancies between government nomenclature (HEALTHBANE), researcher naming (APT-MEDAGENT), and automated commercial tags (VITALSCORE) prevent a definitive geopolitical or criminal attribution. |
| **Missing Victim Telemetry** | Lack of centralized reporting across external healthcare partners limits visibility into the true sector-wide success rate. |
| **Incomplete Stage 3 Visibility** | Network encryption obscures the exact contents of payloads exfiltrated during the final phase. |
| **Commercial-Feed Uncertainty** | High volume of noisy, uncorroborated indicators in commercial feeds introduces ambiguity that requires rigorous triage. |

**Recommended Collection to Fill Gaps:** Deployment of advanced endpoint detection and response (EDR) memory scanning across all healthcare assets, enhanced NetFlow traffic analysis for encrypted egress channels, and active threat-hunting collaboration via ISAC sharing forums.
