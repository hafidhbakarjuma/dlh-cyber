# 13. The Web Exposure Analysis

This analysis categorizes vulnerabilities based on network exposure, demonstrating why an internet-facing vulnerability fundamentally differs from an internal one in terms of risk and priority.

---

## 1. Patient Portal Web Server
* **Host:** `portal-web-01` (10.10.1.20)
* **Exposure:** Internet-facing
* **Findings:**
    * Finding 005: Missing Security Headers (HSTS, CSP)
    * Finding 007: Weak TLS Configuration (TLS 1.0/1.1 enabled)
    * Finding 014: Information Disclosure (Server version banner)
* **Combined Risk:** High. The combination of weak encryption and information disclosure provides attackers with the necessary reconnaissance to launch targeted attacks against the portal.
* **Attack Scenario:** An attacker performs reconnaissance via the disclosed version (Finding 014), downgrades the connection via weak TLS (Finding 007), and exploits a latent application vulnerability, potentially leading to unauthorized patient data access (Phase 2).
* **Priority:** 1 (Highest, due to direct internet exposure).

---

## 2. EHR Application Server
* **Host:** `ehr-srv-01` (10.10.2.10)
* **Exposure:** Internal but flat network accessible
* **Findings:**
    * Finding 031: Ghostcat Vulnerability (CVE-2020-1938)
    * Finding 017: Apache Tomcat Information Disclosure
* **Combined Risk:** Critical. Despite being internal, the flat network architecture makes this accessible to any compromised host, and the RCE capability of Ghostcat makes this a primary target.
* **Attack Scenario:** After gaining initial access to the internal network, an attacker uses the information disclosed in Finding 017 to target the Ghostcat vulnerability (Finding 031), enabling file read or RCE to steal database credentials (Phase 3).
* **Priority:** 2 (High, due to the critical impact of EHR compromise).

---

## 3. NAS Management Interface
* **Host:** `nas-mgmt-01` (10.10.2.50)
* **Exposure:** Internal-only
* **Findings:**
    * Finding 022: Default Administrator Credentials
    * Finding 025: Insecure HTTP interface
* **Combined Risk:** Moderate. The risk is high only if an attacker is already present on the network, but the ease of access makes it a high-value lateral movement target.
* **Attack Scenario:** Once an attacker establishes an internal foothold, they access the insecure HTTP interface (Finding 025) and use the default credentials (Finding 022) to take over the storage, exfiltrating patient backups (Phase 4).
* **Priority:** 3 (Moderate, requires an initial internal foothold).

---

## The Value of Investigating "Medium" Findings

Finding 017 (Tomcat information disclosure) was the catalyst for identifying Finding 031 (Ghostcat - CVSS 9.8). This underscores a critical reality in vulnerability management: **"Medium" findings are often the "keys to the kingdom."** 

Automated scanners frequently label information disclosure (like server banners or version numbers) as "Medium" or "Low" because they are not direct exploits. However, these findings provide the precise "map" an attacker needs to search for known vulnerabilities in their exploit toolkit. If the security team ignores these "Medium" alerts, they are essentially providing attackers with a roadmap of the infrastructure's weaknesses. Manual investigation of these disclosures is often the difference between proactively securing an environment and waiting for a breach to occur.
