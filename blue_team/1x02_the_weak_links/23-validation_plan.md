# 22. The Validation Plan

## 1. Post-Patch Verification (Immediate Remediations)

| Finding | Remediation | Verification Method |
| :--- | :--- | :--- |
| **001 (FortiGate)** | Firmware Patch | Verify version string via CLI/GUI; rescan via OpenVAS to confirm CVE-2024-21762 is no longer reported; test VPN authentication flow. |
| **002 (DC-01)** | KB Patch | Confirm system file versions correspond to patch level; run `Get-HotFix` in PowerShell; verify SMB signing is enabled. |
| **003/031 (EHR)** | Tomcat Patch | Verify version/AJP status; attempt non-invasive exploit check against port 8009 to confirm closure; perform application smoke test. |

## 2. Compensating Control Validation
*   **MRI Workstation (Finding 018/004)**: Verify network isolation by attempting to ping or traceroute to restricted subnets; confirm via firewall logs that all non-essential egress traffic is dropped.
*   **Medical IoT (Alaris Pumps)**: Perform periodic network traffic analysis (PCAP) to ensure devices only communicate with authorized controller/gateway IPs and block all other outbound traffic attempts.

## 3. Rescan Schedule
*   **Recommendation**: Monthly full-environment scans, with **immediate** ad-hoc rescans after any high/critical patch application.
*   **Justification**: A monthly cadence satisfies compliance (HIPAA) and provides a predictable rhythm for IT/Security, while ad-hoc scans provide necessary "trust but verify" assurance for urgent remediation.

## 4. Continuous Intelligence Integration
*   **CISA KEV**: Weekly automated review of the CISA KEV catalog; if a new entry matches our inventory, move to "Immediate" priority.
*   **Vendor Advisories**: Centralized RSS feed aggregation for critical hardware (Fortinet) and software (Apache, Microsoft).
*   **Threat Feeds**: Integration of threat actor indicators (IOCs) into the SIEM to detect exploitation attempts *before* they succeed.

## 5. Continuous Vulnerability Management Lifecycle

| Step | Action | Responsibility |
| :--- | :--- | :--- |
| **Scan** | Automated network-wide discovery | Security Analyst |
| **Triage** | Risk categorization/False positive removal | Security Analyst |
| **Prioritize** | Mapping to assets/threat context | Management/Security |
| **Remediate** | Patch/Config change implementation | IT Ops / Vendor |
| **Validate** | Verification of remediation success | Security Analyst |
| **Repeat** | Cycle back to Scan | All |

---

*This Validation Plan ensures that security controls are not only deployed but verified, closing the loop on the vulnerability lifecycle.*
