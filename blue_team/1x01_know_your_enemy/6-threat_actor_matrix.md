# MedDefense Threat Actor Matrix

## Threat Actor Assessment

| Threat Actor | Likelihood | Capability | Motivation | Preferred Vector | Primary Target | MedDefense Exposure |
|---|---|---|---|---|---|---|
| **Ransomware Groups (Organized Crime)** | **Very High** - Healthcare is a top target due to critical services and sensitive data. | **High** - RaaS groups use advanced malware, affiliates, and data extortion. | Financial gain through ransom and stolen data. | Phishing, stolen credentials, unpatched systems, vendor compromise. | EHR, patient data, backups, hospital operations. | G1 Flat network, G2 Weak MFA/access control, G3 Backup weaknesses, G4 Patch issues, G5 Limited monitoring. |
| **Nation-State APT** | **Medium** - Healthcare data and research can provide intelligence value. | **Very High** - Uses advanced tools, custom malware, and persistence techniques. | Espionage and strategic advantage. | Spear phishing, zero-day exploits, supply chain attacks. | Medical research, patient data, infrastructure. | G4 Patch weaknesses, G5 Monitoring gaps, G6 Vendor risks. |
| **Insider (Malicious)** | **Medium** - Employees with access can intentionally abuse systems. | **Medium-High** - Depends on privileges and knowledge. | Data theft, revenge, financial gain. | Credential misuse, privilege abuse, unauthorized access. | Patient records and sensitive systems. | G2 Access control gaps, G7 Weak monitoring, G8 Data governance issues. |
| **Insider (Negligent)** | **Very High** - Human error is a major healthcare risk. | **Low-Medium** - Requires little technical skill. | Accidental mistakes and unsafe behavior. | Phishing, weak passwords, accidental sharing. | Email, credentials, patient information. | G2 Weak authentication, G9 Lack of training, G10 Endpoint weaknesses. |
| **Hacktivist** | **Low-Medium** - Depends on political or social interest. | **Medium** - Skills vary from basic to advanced. | Political messaging and reputation damage. | DDoS, website attacks, data leaks. | Public systems and sensitive documents. | G5 Monitoring gaps, G10 External security weaknesses. |
| **Unskilled/Opportunistic Attacker** | **High** - Automated attacks constantly scan exposed systems. | **Low** - Uses public tools and known exploits. | Curiosity, experimentation, easy financial gain. | Scanning, weak passwords, exposed services. | Public applications and user accounts. | G2 Weak authentication, G4 Unpatched systems, G10 Endpoint gaps. |

---

# Top 3 Priority Ranking

## 1. Ransomware Groups (Organized Crime) - Critical

Ransomware is the highest threat because it combines high likelihood with severe operational impact. Healthcare organizations are frequently targeted because attackers know downtime affects patient care. MedDefense weaknesses in network segmentation, backups, identity protection, and monitoring increase the risk.

## 2. Insider (Negligent) - High

Negligent insiders are a major risk because employees can accidentally expose systems through phishing, weak passwords, or unsafe behavior. Improving security awareness, MFA, and endpoint protection will reduce this threat.

## 3. Insider (Malicious) - High

Malicious insiders can use legitimate access to steal patient information or damage systems. Strong access controls, least privilege, and monitoring are required to reduce this risk.

---

# Board Summary

| Rank | Threat Actor | Risk |
|---|---|---|
| 1 | Ransomware Groups | Critical |
| 2 | Insider (Negligent) | High |
| 3 | Insider (Malicious) | High |
| 4 | Nation-State APT | Medium-High |
| 5 | Opportunistic Attackers | Medium |
| 6 | Hacktivists | Low-Medium |

## Conclusion

MedDefense should prioritize:
- Ransomware protection
- Strong identity security and MFA
- Employee security awareness training
- Improved monitoring and SIEM visibility
- Third-party/vendor risk management
