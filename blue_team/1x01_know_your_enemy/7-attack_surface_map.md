# MedDefense Attack Surface Map

## Section 1: External Surface (Internet Accessible)

| Entry Point | Asset Behind It | Existing Protection | Gap Reference |
|---|---|---|---|
| **Patient Portal** | web-srv-01 hosting patient-facing services and healthcare applications. | Firewall protection and web server controls. | G4 Patch Management Weakness, G5 Limited Monitoring, G2 Weak Identity Controls. |
| **VPN Endpoint** | Remote access into MedDefense internal network. | VPN authentication controls. | G2 Weak MFA/Authentication, G5 Limited Logging and Monitoring. |
| **Email Infrastructure (Microsoft 365)** | Employee email accounts and communication systems. | Microsoft 365 security features and spam filtering. | G9 Security Awareness Gap, G2 Weak Authentication Controls. |
| **Public Website** | Public-facing web server and organizational information. | Firewall and basic web protections. | G4 Vulnerable Software, G5 Monitoring Gaps. |
| **DNS Services** | Domain resolution and external service discovery. | DNS configuration controls. | G5 Limited Monitoring, G4 Configuration Management Weakness. |
| **External Services/Vendors** | Third-party systems connected to MedDefense operations. | Vendor agreements and access controls. | G6 Third-Party Risk Management Weakness. |

### External Surface Risk

Internet-facing systems provide attackers with opportunities for reconnaissance, vulnerability scanning, phishing support, and initial access attempts.

---

# Section 2: Internal Surface (Inside Network)

MedDefense's biggest internal concern is the **flat network architecture**. Once an attacker gains access, limited segmentation allows easier movement between systems.

| Asset | Exposure (Port/Service) | Why It Matters | Gap Reference |
|---|---|---|---|
| **billing-srv-01** | MySQL port 3306 accessible network-wide. | Attackers can target databases containing financial and operational data and move further into the network. | G1 Flat Network, G4 Patch Weakness, G5 Monitoring Gap. |
| **ehr-db-01** | PostgreSQL port 5432 accessible network-wide. | Exposes sensitive healthcare databases and increases patient data theft risk. | G1 Network Segmentation, G2 Access Control Weakness. |
| **Employee Workstations** | RDP access available on selected systems. | Compromised credentials could allow attackers remote access and lateral movement. | G2 Weak Authentication, G5 Monitoring Gap. |
| **NAS Storage** | Management interface accessible internally. | Attackers could target shared files, backups, and sensitive documents. | G1 Flat Network, G5 Monitoring Weakness. |
| **FortiGate Administration Interface** | Internal management access. | Compromise could provide control over network security devices. | G2 Privilege Management Weakness. |
| **Medical IoT Devices** | Web-based management interfaces. | Attackers may control devices or use them as entry points. | G2 Default Credentials, G10 IoT Security Weakness. |
| **PACS System** | Shared/default accounts. | Attackers can access medical images and patient information. | G2 Identity Management Weakness. |
| **Legacy Systems** | Windows XP MRI workstation, Windows Server 2012 R2 print server. | Unsupported systems provide exploitable weaknesses and malware entry points. | G4 Unsupported Systems. |

### Internal Surface Risk

The flat network increases the impact of any successful compromise because attackers can move from low-value systems to critical healthcare assets.

---

# Section 3: Human Surface (People as Attack Targets)

| Role | Access Level | Why They Are Targeted | Control Gap |
|---|---|---|---|
| **Clinical Staff** | Access to EHR, patient records, medical systems. | Large user group, frequent phishing targets, high-value data access. | G9 Security Awareness Training Gap, G2 Weak Authentication. |
| **Reception Staff** | Patient information systems and physical access areas. | First point of contact and vulnerable to social engineering. | G9 Security Awareness Gap. |
| **IT Staff** | Administrative privileges across infrastructure. | Small team creates fatigue risk; compromise provides high impact access. | G2 Privilege Management Weakness, G5 Monitoring Gap. |
| **Executives** | Business information, financial systems, strategic data. | Common targets for Business Email Compromise (BEC). | G9 Phishing Awareness Gap, G2 MFA Weakness. |
| **External Contractors** | Vendor systems and possible internal access. | Access may not be fully controlled by MedDefense. | G6 Third-Party Risk Weakness. |

---

# Surface Assessment Summary

MedDefense's greatest current risk is the **internal attack surface**, mainly because of the flat network architecture. While external systems create opportunities for attackers to enter, weak segmentation allows a single compromised account or device to become a pathway to critical systems such as EHR databases, medical devices, and backups. Combined with weak identity controls, outdated systems, and human vulnerabilities, MedDefense faces a high risk of lateral movement and major operational disruption.
