# Detection Gap Analysis: HEALTHBANE Campaign

## 1. Comprehensive Technique Assessment

### Initial Access

#### T1566.001 — Phishing: Spearphishing Attachment

| Field | Details |
|-------|---------|
| **Status** | OBSERVED |
| **Detection Status** | DETECTED |
| **Evidence** | Covered by mail gateway file reputation scanning and YARA rules targeting PDF object streams containing suspicious URIs. |
| **Gap Explanation** | Evasion possible via newly registered PDF packing formats or zero-day compression methods. |
| **Recommendation** | Enhance email gateway inspection with deep sandbox detonation. |

#### T1566.002 — Phishing: Spearphishing Link

| Field | Details |
|-------|---------|
| **Status** | OBSERVED |
| **Detection Status** | DETECTED |
| **Evidence** | Documented IOC domain blocklists (`meddefense-portal.com`, `medequip-supplies.net`) implemented at web proxies and DNS filters. |
| **Gap Explanation** | Rapid domain generation algorithms (DGAs) or fast-flux hosting can bypass static lists before blacklists update. |
| **Recommendation** | Deploy real-time URL categorization and SSL/TLS inspection heuristics. |

#### T1192 — Phishing (Legacy / General Campaign Indicator)

| Field | Details |
|-------|---------|
| **Status** | INFERRED |
| **Detection Status** | PARTIALLY DETECTED |
| **Evidence** | General outbound email filtering monitors volumetric sending trends, but lacks behavioral context for broad external campaigns. |
| **Gap Explanation** | Low visibility into external domains spoofing external vendor partners. |
| **Recommendation** | Implement DMARC/DKIM enforcement and automated external domain lookalike monitoring. |

---

### Execution

#### T1204.002 — User Execution: Malicious File

| Field | Details |
|-------|---------|
| **Status** | OBSERVED |
| **Detection Status** | PARTIALLY DETECTED |
| **Evidence** | Endpoint process creation logs record PDF reader executions, but distinguishing malicious user interaction from benign document opening remains challenging. |
| **Gap Explanation** | Lack of direct application-layer correlation between PDF process execution and outbound browser navigation to phishing URIs. |
| **Recommendation** | Deploy endpoint detection rules triggering alerts when PDF readers spawn web browser child processes or execute external URI handlers. |

#### T1059.003 — Command and Scripting Interpreter: Windows Command Shell

| Field | Details |
|-------|---------|
| **Status** | INFERRED |
| **Detection Status** | NOT DETECTED |
| **Evidence** | No direct telemetry or command line audit logs currently configured for standard administrative script execution blocks. |
| **Gap Explanation** | Blind spot in standard user workstation command auditing. |
| **Recommendation** | Enable PowerShell and Command Shell process argument logging (Event ID 4688 with command line auditing). |

---

### Credential Access

#### T1566 — Phishing for Credentials

| Field | Details |
|-------|---------|
| **Status** | OBSERVED |
| **Detection Status** | DETECTED |
| **Evidence** | Credential monitoring services and internal SIEM alerts track abnormal authentication failures and impossible travel logins. |
| **Gap Explanation** | Hard to detect credential harvesting if users voluntarily submit valid credentials to authentic-looking fake SSO portals. |
| **Recommendation** | Mandate hardware-backed multi-factor authentication (MFA) resistant to phishing (e.g., FIDO2/WebAuthn). |

#### T1588.002 — Obtain Capabilities: Tool

| Field | Details |
|-------|---------|
| **Status** | INFERRED |
| **Detection Status** | NOT DETECTED |
| **Evidence** | Pre-attack acquisition of tools or templates occurs entirely externally. |
| **Gap Explanation** | No internal visibility into threat actor staging environments. |
| **Recommendation** | Rely on external threat intelligence subscription feeds and collaborative ISAC intelligence sharing. |

#### T1539 — Steal Web Session Cookie

| Field | Details |
|-------|---------|
| **Status** | INFERRED |
| **Detection Status** | NOT DETECTED |
| **Evidence** | Session token monitoring lacks anomaly detection for anomalous token access from foreign IP spaces. |
| **Gap Explanation** | Insufficient continuous session validation and device posture checks. |
| **Recommendation** | Implement strict conditional access policies binding session cookies to device identifiers. |

---

### Defense Evasion

#### T1027 — Obfuscated Files or Information

| Field | Details |
|-------|---------|
| **Status** | OBSERVED |
| **Detection Status** | PARTIALLY DETECTED |
| **Evidence** | Static YARA rules identify obfuscated PDF object streams, but dynamic obfuscation layers can bypass signature scans. |
| **Gap Explanation** | Signature-based engines fail against custom packing or encrypted object containers. |
| **Recommendation** | Implement memory inspection and behavioral anomaly detection on endpoint document viewers. |

---

### Command and Control

#### T1071.001 — Application Layer Protocol: Web Protocols

| Field | Details |
|-------|---------|
| **Status** | OBSERVED |
| **Detection Status** | PARTIALLY DETECTED |
| **Evidence** | Firewalls log outbound HTTPS traffic, but standard web traffic is generally permitted across corporate networks, masking C2 beacons. |
| **Gap Explanation** | High volume of legitimate HTTPS traffic makes identifying low-and-slow C2 beacons difficult without behavioral traffic analysis. |
| **Recommendation** | Deploy network traffic analysis (NTA) tools monitoring for JA3/JA4 SSL client fingerprint anomalies and beaconing periodicity. |

#### T1573.001 — Encrypted Channel: Symmetric Cryptography

| Field | Details |
|-------|---------|
| **Status** | INFERRED |
| **Detection Status** | NOT DETECTED |
| **Evidence** | Standard enterprise TLS decryption policies exclude sensitive medical and HR traffic due to privacy compliance. |
| **Gap Explanation** | Blind spots in encrypted payload inspection. |
| **Recommendation** | Implement selective SSL/TLS interception for untrusted external domains and anomalous destination categories. |

---

### Exfiltration

#### T1041 — Exfiltration Over C2 Channel

| Field | Details |
|-------|---------|
| **Status** | OBSERVED |
| **Detection Status** | PARTIALLY DETECTED |
| **Evidence** | Data loss prevention (DLP) gateways monitor bulk exports, but small-scale credential or billing data exfiltration over encrypted HTTPS channels goes unnoticed. |
| **Gap Explanation** | Low-volume data leakage blends seamlessly into normal web browsing sessions. |
| **Recommendation** | Configure behavioral anomaly alerts for abnormal outbound data volume spikes to newly resolved external IP addresses. |

---

## 2. Prioritized Gap List & Action Plan

| Priority | Technique ID | Technique Name | Status | Why the Gap Matters | Detection Idea | Required Data Source | Suggested Owner |
|----------|--------------|----------------|--------|---------------------|----------------|----------------------|-----------------|
| **Priority 1** | T1059.003 | Command & Scripting Interpreter | INFERRED (Not Detected) | Enables secondary payloads and lateral movement post-lure engagement. | Alert on anomalous command shell spawns from document viewers or browsers. | Endpoint Process Logging (Sysmon Event ID 1 / Windows Security 4688) | Endpoint Security Team |
| **Priority 1** | T1539 | Steal Web Session Cookie | INFERRED (Not Detected) | Bypasses traditional MFA if session tokens are hijacked or phished. | Monitor for concurrent session access from divergent geographic locations. | Cloud Identity & SSO Access Logs | Identity & Access Management |
| **Priority 2** | T1573.001 | Encrypted Channel: Symmetric Cryptography | INFERRED (Not Detected) | Blinds defenders to C2 communications and data exfiltration payloads. | Monitor TLS handshake characteristics (JA3/JA4 fingerprints) for known malicious tooling. | Network Flow & Firewall Logs | Network Security Team |
| **Priority 3** | T1204.002 | User Execution: Malicious File | OBSERVED (Partially Detected) | Represents the primary human vulnerability point in the infection chain. | Detect PDF reader processes spawning network connection requests or script interpreters. | Endpoint Process & Network Telemetry | SOC Detection Engineering |
