# 16. The Noise Filter: Triage Assessment

| ID | Severity | Host | Category | Reason |
| --- | --- | --- | --- | --- |
| 001 | Critical | FortiGate 100F | AC | Internet-facing RCE (CVE-2024-21762) requires immediate patching to prevent total network compromise. |
| 002 | Critical | Domain Controller (DC-01) | AC | Critical SMB vulnerability (EternalBlue) on identity provider enables domain-wide ransomware propagation. |
| 003 | Critical | EHR-SRV-01 | AC | Ghostcat (CVE-2020-1938) allows RCE on the primary patient record database. |
| 004 | High | Workstation-RAD-01 | AC | Outdated OS (Windows XP) is permanently vulnerable and must be isolated immediately. |
| 005 | Medium | Portal-Web-01 | AS | Missing security headers (HSTS, CSP) should be implemented to improve browser-side security. |
| 006 | High | Medical-IoT-Gateway | AC | Hard-coded credentials allow unauthorized access to medical device traffic. |
| 007 | Medium | Portal-Web-01 | AS | Weak TLS configuration (TLS 1.0) needs to be upgraded to TLS 1.3. |
| 008 | High | BD-Alaris-01 | AC | Critical infusion pump firmware vulnerability (CVE-2023-30559) poses direct patient safety risk. |
| 009 | High | BD-Alaris-02 | AC | Critical infusion pump firmware vulnerability (CVE-2023-30559) poses direct patient safety risk. |
| 010 | High | Philips-Monitor-01 | AS | Unauthenticated HL7 port exposed; needs network ACLs for restriction. |
| 011 | Medium | Billing-Srv-01 | AS | Unencrypted administrative interface over HTTP requires migration to HTTPS. |
| 012 | Low | Workstation-Admin-05 | I | Minor local configuration drift that does not impact security posture. |
| 013 | Medium | EHR-SRV-01 | AS | Apache Tomcat version information disclosure helps attackers map the attack surface. |
| 014 | Medium | Portal-Web-01 | AS | Server version banner disclosure facilitates targeted reconnaissance. |
| 015 | Low | Workstation-Nurse-12 | I | Inconsequential software versioning warning. |
| 016 | High | Philips-Monitor-02 | AS | Exposed web management interface on patient monitor; needs isolation. |
| 017 | Medium | EHR-SRV-01 | AS | Insecure directory listing enabled on internal app server. |
| 018 | Low | Network-Switch-04 | I | Banner grabbing allows detection of device type but no exploit capability. |
| 019 | High | Domain Controller (DC-02) | AC | Unpatched PrintNightmare vulnerability allows domain escalation. |
| 020 | Medium | File-Srv-01 | AS | SMB signing not enforced allows potential relay attacks. |
| 021 | High | NAS-Mgmt-01 | AC | Default admin credentials on storage management interface. |
| 022 | High | NAS-Mgmt-01 | AS | Insecure HTTP interface for device management. |
| 023 | Low | Printer-HR-01 | I | Outdated SNMP version; low risk due to isolated management VLAN. |
| 024 | High | BD-Alaris-03 | AC | Firmware vulnerability (CVE-2023-30560) allows physical-to-network authentication bypass. |
| 025 | Medium | NAS-Mgmt-01 | AS | Weak password policy for local administrative accounts. |
| 026 | Low | Workstation-Finance-02 | I | Non-sensitive software update reminder. |
| 027 | Low | Lab-Device-04 | FP | Scanner misidentified a proprietary binary as a known exploit; dismissed. |
| 028 | Medium | VPN-Concentrator | AS | Excessive session timeout settings need tightening. |
| 029 | Low | Guest-Wifi-AP | I | Default vendor documentation file accessible via web. |
| 030 | Medium | Email-Srv-01 | AS | Incomplete SPF record configuration. |
| 031 | Critical | EHR-SRV-01 | AC | Confirmed Ghostcat exploitability on internal application server. |

## Triage Summary
* **Actionable Critical (AC):** 11
* **Actionable Standard (AS):** 13
* **Informational (I):** 6
* **False Positive (FP):** 1

## Actionable Findings List
### Actionable Critical (Immediate Remediation)
* **001**: FortiGate 100F - Internet-facing RCE (CVE-2024-21762) requires immediate patching to prevent total network compromise.
* **002**: Domain Controller (DC-01) - Critical SMB vulnerability (EternalBlue) on identity provider enables domain-wide ransomware propagation.
* **003**: EHR-SRV-01 - Ghostcat (CVE-2020-1938) allows RCE on the primary patient record database.
* **004**: Workstation-RAD-01 - Outdated OS (Windows XP) is permanently vulnerable and must be isolated immediately.
* **006**: Medical-IoT-Gateway - Hard-coded credentials allow unauthorized access to medical device traffic.
* **008**: BD-Alaris-01 - Critical infusion pump firmware vulnerability (CVE-2023-30559) poses direct patient safety risk.
* **009**: BD-Alaris-02 - Critical infusion pump firmware vulnerability (CVE-2023-30559) poses direct patient safety risk.
* **019**: Domain Controller (DC-02) - Unpatched PrintNightmare vulnerability allows domain escalation.
* **021**: NAS-Mgmt-01 - Default admin credentials on storage management interface.
* **024**: BD-Alaris-03 - Firmware vulnerability (CVE-2023-30560) allows physical-to-network authentication bypass.
* **031**: EHR-SRV-01 - Confirmed Ghostcat exploitability on internal application server.

### Actionable Standard (Scheduled Remediation)
* **005**: Portal-Web-01 - Missing security headers (HSTS, CSP) should be implemented to improve browser-side security.
* **007**: Portal-Web-01 - Weak TLS configuration (TLS 1.0) needs to be upgraded to TLS 1.3.
* **010**: Philips-Monitor-01 - Unauthenticated HL7 port exposed; needs network ACLs for restriction.
* **011**: Billing-Srv-01 - Unencrypted administrative interface over HTTP requires migration to HTTPS.
* **013**: EHR-SRV-01 - Apache Tomcat version information disclosure helps attackers map the attack surface.
* **014**: Portal-Web-01 - Server version banner disclosure facilitates targeted reconnaissance.
* **016**: Philips-Monitor-02 - Exposed web management interface on patient monitor; needs isolation.
* **017**: EHR-SRV-01 - Insecure directory listing enabled on internal app server.
* **020**: File-Srv-01 - SMB signing not enforced allows potential relay attacks.
* **022**: NAS-Mgmt-01 - Insecure HTTP interface for device management.
* **025**: NAS-Mgmt-01 - Weak password policy for local administrative accounts.
* **028**: VPN-Concentrator - Excessive session timeout settings need tightening.
* **030**: Email-Srv-01 - Incomplete SPF record configuration.
