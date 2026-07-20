# Security Strategy Document: MedDefense Health Systems

## 1. Executive Summary
MedDefense is currently operating with a high-risk posture characterized by a flat network, lack of multi-factor authentication (MFA) on critical systems, and significant visibility gaps. Our strategic approach adopts the NIST Cybersecurity Framework (CSF) and CIS Controls to systematically move from a reactive to a resilient security maturity model. We request a total investment of $250,000 to achieve a projected 65% reduction in annualized loss expectancy (ALE). Our top three priority actions are:
*   Implementation of immutable offsite backups to neutralize ransomware impact.
*   Deployment of MFA across all VPN and administrative access points.
*   Execution of network segmentation to isolate clinical and medical device zones.

## 2. Governance Framework
*   **Framework Rationale**: NIST CSF was selected for its alignment with healthcare regulatory requirements, while CIS Controls provide the actionable technical safeguards needed for rapid implementation.
*   **NIST CSF Summary**: We are targeting a move from a Current Profile of "Level 1 (Partial)" to a Target Profile of "Level 3 (Defined)" over the next 18 months.
*   **CIS Maturity**: Current maturity is assessed at 1.2; the target is 2.5 by the end of the 6-month roadmap.
*   **Structure**: The Deputy CISO holds operational ownership, with the Security Steering Committee providing monthly oversight.

## 3. Quantitative Risk Analysis
*   **Top 5 Risks by ALE**:
    1. RISK-001: Ransomware/Backup destruction ($468,300)
    2. RISK-002: VPN credential theft ($375,550)
    3. RISK-003: EHR encryption via flat network ($370,800)
    4. RISK-004: Negligent insider data exposure ($300,000)
    5. RISK-005: Undetected malware dwell time ($106,800)
*   **Risk Appetite**: MedDefense prioritizes patient safety; risks threatening life-critical systems are mitigated regardless of cost, while operational risks follow a strict cost-benefit justification.

## 4. Control Strategy
*   **Budget Allocation**: $150,000 for technical controls (MFA/Segmentation), $60,000 for operational staffing, and $40,000 for emergency reserve.
*   **Quick Wins**: Implementation of account auditing, screen lock enforcement, and Guest Wi-Fi isolation will be completed within the first 14 days.

## 5. Architecture Recommendations
*   **Segmentation**: Transitioning from a flat network to five distinct zones: Server, Clinical Workstation, Medical Device, Management, and Guest/IoT.
*   **Kill Chain Impact**: The segmentation design disrupts 80% of our primary ransomware kill chains by preventing lateral movement and restricting outbound C2 traffic.

## 6. Policy Foundation
*   **AUP Summary**: Mandatory compliance for all staff regarding credential sharing, removable media, and incident reporting.
*   **Policy Roadmap**: Upcoming policies include Data Classification (Month 3) and Third-Party Risk Management (Month 5).

## 7. Residual Risk Assessment
*   **Red Team Findings**: Despite planned controls, targeted human-operated attacks exploiting unmonitored administrative pathways remain a Medium residual risk.
*   **Year 2 Priorities**: Deployment of 24/7 Managed Detection and Response (MDR) and comprehensive Data Loss Prevention (DLP).

## 8. Implementation Roadmap
*   **Phase 1 (Months 1-2)**: Quick wins, MFA rollout, and backup hardening.
*   **Phase 2 (Months 3-4)**: Core network segmentation and device isolation.
*   **Phase 3 (Months 5-6)**: Continuous monitoring setup and program validation.
*   **Success Metrics**: 90% MFA coverage; 0 critical findings in follow-up scan; successful completion of backup restoration tests.

## 9. Next Steps
The transition from this strategic document to Project 1x04 (Cryptographic Foundation) involves integrating hardware security modules (HSM) for key management and encrypting data-at-rest across all primary databases.
