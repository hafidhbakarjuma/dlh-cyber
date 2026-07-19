# 18. The Threat-Vulnerability Correlation Matrix

| ID | Threat Actor(s) | Vector | Kill Chain | Scenario | Gap |
| --- | --- | --- | --- | --- | --- |
| 001 | LockBit, APT28 | Public Application Exploit | Initial Access | Internet-to-Internal Pivot | Lack of perimeter hardening |
| 002 | LockBit | Lateral Movement | Persistence/Privilege Escalation | Domain Domination | Flat network architecture |
| 003 | Lazarus Group, LockBit | Application Exploitation | Data Exfiltration | Targeted PHI Exfiltration | Unrestricted internal access |
| 004 | LockBit | Lateral Movement | Exploitation | Ransomware Propagation | Legacy/EOL OS usage |
| 006 | APT28 | Credential Exploitation | Initial Access | Backdoor Installation | Security oversight/Default config |
| 008 | APT28 | Exploitation | Targeted Sabotage | Patient Care Disruption | Medical device insecure configuration |
| 009 | APT28 | Exploitation | Targeted Sabotage | Patient Care Disruption | Medical device insecure configuration |
| 031 | Lazarus Group, LockBit | Application Exploitation | Data Exfiltration | Targeted PHI Exfiltration | Lack of application segmentation |

## Strategic Conclusion
Exploitation of Finding 003 (Ghostcat on the EHR Application Server) would cause the most damage in the current threat context. As the central repository for patient health information (PHI) and clinical operations, the EHR is the ultimate 'crown jewel.' An actor like the Lazarus Group or LockBit could leverage this RCE to perform wide-scale PHI exfiltration or trigger a total clinical shutdown, with the flat network ensuring that no other system can contain the damage once the EHR is breached, effectively paralyzing the entire facility.
