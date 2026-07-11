# MedDefense

# Comparative Assessment and Future Threat Perspective

---

# Part 1 – Comparative Analysis

| Finding | Marcus's Assessment | Your Assessment | Agree / Disagree | Resolution |
|----------|--------------------|-----------------|------------------|------------|
| Network Segmentation | Flat network allows unrestricted lateral movement. | Identified as **GAP-012 (Critical)** requiring VLANs and internal firewalls. | **Agree** | Both assessments conclude that network segmentation is the highest priority because it limits attacker movement and protects critical systems. |
| Backup Isolation | Backups are stored on the same network as production systems. | Identified as **GAP-010 (Critical)** requiring immutable off-site backups. | **Agree** | Real-world ransomware incidents confirm that isolated backups are essential for recovery. |
| Medical IoT Exposure | Medical devices share the production network and use default credentials. | Identified as **GAP-001 (Critical)** and **GAP-017 (Critical)** | **Agree** | Both assessments recognize medical devices as a major patient safety and cybersecurity risk. |
| Monitoring & Detection | No SIEM, IDS, centralized logging or alerting. | Identified through **GAP-006**, **GAP-009**, with monitoring recommendations. | **Agree** | Lack of detective controls significantly increases attacker dwell time. |
| No Multi-Factor Authentication | VPN, EHR and administrator accounts rely only on passwords. | Added as **GAP-015 (Critical)** | **Agree** | Healthcare breaches consistently show stolen credentials as a primary attack vector. |
| Westside Clinic Security | Consumer-grade networking equipment and weak physical security. | Not identified during initial assessment. | **Agree (Missed)** | This is a valid finding and should be added to the gap register. |
| Shared Radiology Credentials | Shared PACS account prevents accountability. | Identified as **GAP-008 (Critical)**. | **Agree** | Individual accountability is required for security monitoring and regulatory compliance. |
| Print Server End-of-Life | Windows Server 2012 R2 no longer supported. | Not identified. | **Partially Agree** | The finding is technically valid but remains a lower priority because higher-risk vulnerabilities require immediate attention. |

---

# Findings Marcus Identified That Were Missed

The following findings were not included in the original MedDefense assessment and should be added.

| New Gap ID | Title | Risk | Justification |
|------------|-------|------|---------------|
| GAP-020 | Westside Clinic Infrastructure Security | High | Consumer-grade firewall, unsecured server room and unrestricted VPN increase enterprise risk. |
| GAP-021 | Legacy Print Server | Low | Unsupported operating system introduces compliance and vulnerability risks. |
| GAP-022 | TLS 1.0 Enabled on Patient Portal | Medium | Deprecated encryption weakens secure communications. |
| GAP-023 | USB Storage Not Restricted | Medium | Allows uncontrolled data exfiltration and malware introduction. |
| GAP-024 | Building Management System Third-Party Risk | Medium | Shared infrastructure introduces supply-chain and network risks outside MedDefense's visibility. |
| GAP-025 | Lack of Formal Change Management | Medium | Uncontrolled configuration changes increase operational and security risk. |

---

# Findings You Identified That Marcus Missed

| Gap ID | Description | Possible Reason Marcus Missed It |
|---------|-------------|----------------------------------|
| GAP-011 | Patch Management Program | Assessment was unfinished before documentation. |
| GAP-013 | Incident Response Plan | Focus was primarily technical rather than procedural. |
| GAP-014 | Automated User Offboarding | Identity governance was outside Marcus's initial scope. |
| GAP-016 | Data Loss Prevention Strategy | Mentioned only briefly in draft notes and never formally documented. |
| GAP-018 | DMZ Misconfiguration | Identified later through real-world breach comparison in Task 13. |
| GAP-019 | Medical Device Firmware Management | Real-world healthcare breach analysis revealed this additional weakness. |

---

# Overall Assessment

Marcus's draft aligns closely with the completed MedDefense assessment. The majority of his highest-risk findings—including network segmentation, backup isolation, medical device exposure, monitoring, and authentication—match the final risk analysis. The differences are primarily the result of his assessment being incomplete rather than technically incorrect. The combined assessments provide a more comprehensive understanding of MedDefense's cybersecurity posture.

---

# Part 2 – Reflection on Marcus's Final Notes

Marcus's unfinished work naturally extends the completed internal security assessment. The internal posture assessment identifies the weaknesses that exist within MedDefense, while the external threat landscape explains which threat actors are most likely to exploit those weaknesses and how they typically operate. By mapping MedDefense's gaps to real-world tactics, techniques, and procedures (TTPs) used by ransomware groups, insider threats, and other attackers, the organization can prioritize defenses against the most probable threats. This makes a formal Threat Landscape Report the logical next step, enabling MedDefense to move from identifying vulnerabilities to proactively anticipating and mitigating attacks.

---
