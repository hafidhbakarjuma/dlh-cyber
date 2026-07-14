# MedDefense Technical Vector Assessment

## Technical Attack Vector Analysis

| Vector Category (Sec+ 2.2) | MedDefense Evidence | Affected Assets | Actor Most Likely to Exploit | Exploitation Scenario | Current Protection | Gap Reference |
|---|---|---|---|---|---|---|
| **Vulnerable Software** | Apache 2.4.29 on billing-srv-01, Ubuntu 18.04 LTS End of Life, outdated software identified during network assessment. | Billing server, web applications, Linux servers. | Ransomware Groups, Opportunistic Attackers, Nation-State APT. | Attackers exploit known vulnerabilities in outdated software to gain initial access or execute code. Compromised servers can be used for lateral movement across the network. | Basic patching processes exist but do not cover all systems. | G4 Patch Management Weakness, G5 Limited Monitoring. |
| **Unsupported Systems** | Windows XP MRI workstation and Windows Server 2012 R2 print server are no longer fully supported. | MRI workstation, print server, medical systems. | Ransomware Groups, Nation-State APT. | Attackers exploit unpatched vulnerabilities in unsupported operating systems because security updates are unavailable. Compromised systems can become entry points into critical healthcare networks. | Existing antivirus and limited administrative controls. | G4 Unsupported Systems, G1 Flat Network Architecture. |
| **Open Service Ports** | MySQL 3306 and PostgreSQL 5432 accessible across the network, RDP exposed on workstations, medical IoT web interfaces available. | Database servers, employee workstations, medical devices. | Opportunistic Attackers, Ransomware Groups. | Attackers scan exposed ports to identify vulnerable services and attempt unauthorized access. Successful compromise may allow data theft or movement to other systems. | Firewall rules provide some filtering but internal access is overly open. | G1 Network Segmentation Weakness, G5 Monitoring Gaps. |
| **Default Credentials** | Shared PACS account, medical device interfaces using default/shared credentials such as BD Alaris pump systems. | PACS, medical devices, clinical systems. | Insider (Malicious), Ransomware Groups, Opportunistic Attackers. | Attackers use known default credentials or shared accounts to access systems without needing advanced exploits. This can expose patient information or allow control of medical devices. | Some account management exists but shared credentials remain. | G2 Weak Identity and Access Management, G8 Poor Account Governance. |
| **Unsecure Networks** | Flat internal network without proper segmentation, Westside consumer router, uncertain WiFi isolation. | Entire hospital network, wireless devices, medical IoT. | Ransomware Groups, Insider Threats, Hacktivists. | Attackers who compromise one device can move easily across the network because systems are not isolated. Weak wireless controls increase the chance of unauthorized access. | Network firewall exists but segmentation controls are limited. | G1 Flat Network Architecture, G10 Wireless Security Weakness. |
| **Removable Devices / Unmanaged Endpoints** | No USB restriction GPO, unmanaged iPads, shadow IT devices connected to environment. | Workstations, mobile devices, clinical endpoints. | Insider (Negligent), Insider (Malicious), Opportunistic Attackers. | Malware can enter through infected USB devices or unmanaged endpoints. Attackers can use these devices to steal data or gain access to internal systems. | Endpoint security tools provide partial protection. | G9 Security Awareness Gap, G10 Endpoint Management Weakness. |

---

# Technical Vector Risk Summary

| Priority | Vector | Risk Level |
|---|---|---|
| 1 | Vulnerable Software & Unsupported Systems | Critical |
| 2 | Open Service Ports | High |
| 3 | Default Credentials | High |
| 4 | Unsecure Networks | High |
| 5 | Removable Devices / Unmanaged Endpoints | Medium-High |

---

# Board Summary

MedDefense's largest technical risks come from outdated systems, exposed services, weak credentials, and insufficient network segmentation. These weaknesses provide attackers with multiple paths for initial access and lateral movement.

Priority improvements:

- Replace unsupported operating systems.
- Establish regular vulnerability and patch management.
- Restrict unnecessary network ports.
- Remove shared/default credentials and enforce MFA.
- Segment medical devices, servers, and user networks.
- Implement endpoint management and USB controls.
