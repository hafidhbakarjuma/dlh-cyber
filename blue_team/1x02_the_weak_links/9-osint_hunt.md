# The OSINT Hunt

## Objective
The vulnerability scan provides good coverage of internal systems but does not assess every component of the MedDefense environment. Public OSINT sources were used to identify additional vulnerabilities and attack techniques affecting technologies used by MedDefense that were not included in the scan.

---

## Finding 1 – FortiGate FortiOS
* **Source:** [Fortinet Security Advisory (FG-IR-24-015)](https://www.fortiguard.com/psirt/FG-IR-24-015) [cite: 0]
* **CVE:** CVE-2024-21762 [cite: 0]
* **Affected Product:** FortiGate 100F (FortiOS) [cite: 0]
* **Why the Scan Missed It:** The vulnerability exists in the SSL VPN component; automated vulnerability scanners often fail to detect specific firmware-level flaws in network appliances unless they have authenticated access or are specifically configured to probe the SSL VPN portal. [cite: 0]
* **CVSS / Severity:** 9.6 – 9.8 (Critical) [cite: 0]
* **MedDefense Impact:** An unauthenticated remote attacker could execute arbitrary code or commands on the firewall, leading to full network perimeter compromise. [cite: 0]
* **Recommendation:** Upgrade to the latest patched firmware version. If patching is not immediately possible, disable the SSL VPN functionality as a temporary mitigation. [cite: 0]

---

## Finding 2 – Microsoft 365 / Entra ID
* **Source:** [Microsoft Entra Security Documentation – OAuth Consent Phishing](https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/overview-consent-and-permissions) [cite: 1]
* **Attack Technique:** OAuth Consent Phishing (No CVE) [cite: 1]
* **Affected Product:** Microsoft 365 E3 / Microsoft Entra ID [cite: 1]
* **Why the Scan Missed It:** The scan was limited to on-premises assets; it lacked the cloud-tenant visibility required to assess OAuth application permissions and user consent settings. [cite: 1]
* **CVSS / Severity:** High [cite: 1]
* **MedDefense Impact:** Attackers can gain persistent access to sensitive data (email, OneDrive, SharePoint) by tricking users into granting "consent" to a malicious application, bypassing traditional MFA requirements. [cite: 1]
* **Recommendation:** Implement a policy to restrict user consent for third-party applications and require administrator approval for new OAuth integrations. [cite: 1]

---

## Finding 3 – Synology DSM
* **Source:** [Synology Security Advisory (Synology_SA_22_18)](https://www.synology.com/security/advisory/Synology_SA_22_18) [cite: 2]
* **CVE:** CVE-2022-27623 [cite: 2]
* **Affected Product:** Synology DSM 7 Backup NAS [cite: 2]
* **Why the Scan Missed It:** The backup appliance was out of scope for the internal vulnerability scan, and the scanner was unable to fingerprint the specific DSM 7 version running on the hardware. [cite: 2]
* **CVSS / Severity:** 7.4 (High) – 9.1 (Critical) [cite: 2]
* **MedDefense Impact:** An attacker could exploit the iSCSI management interface to read or write arbitrary files, potentially allowing them to compromise, exfiltrate, or delete critical medical backup data. [cite: 2]
* **Recommendation:** Update DSM to version 7.1-42661 or higher. Restrict management access to the NAS to an isolated management VLAN and require MFA for all administrative accounts. [cite: 2]

---

## Conclusion
The manual OSINT research successfully identified critical risks that automated tools overlooked. These findings emphasize that a robust security posture must include continuous monitoring of vendor advisories (such as Fortinet and Synology) and the implementation of cloud-native security configurations for platforms like Entra ID.
