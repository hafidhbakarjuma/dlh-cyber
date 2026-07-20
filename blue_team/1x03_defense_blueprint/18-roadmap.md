# 6-Month Security Roadmap: MedDefense Health Systems

This roadmap outlines the critical path for security maturation, designed for tracking by the IT Director and the Security Steering Committee.

## Monthly Implementation Breakdown

| Month | Actions | Responsible Owner | Dependencies | Completion Criteria |
| :--- | :--- | :--- | :--- | :--- |
| **1** | Quick Wins (Account cleanup, GPO lockouts) | Security Analyst | None | All Quick Wins verified via audit |
| **2** | MFA rollout (VPN/Admin); Backup hardening | IT Director | None | 100% MFA on targeted accounts |
| **3** | Network Segmentation (Phase 1) | Network Engineer | Asset Inventory | VLANs segmented; traffic validated |
| **4** | Medical Device Isolation | Security Analyst | Segmentation | No unapproved traffic to devices |
| **5** | SIEM Deployment (Wazuh) | Security Analyst | Log sourcing | Logs ingested; alerts functional |
| **6** | Validation & Program Audit | Deputy CISO | All prior phases | Zero critical findings in audit |

---

## Dependency Chain

1.  **Network Segmentation (Month 3) → Medical Device Isolation (Month 4)**: The segmentation VLANs must be architected and deployed before individual medical devices can be moved into protected zones.
2.  **Asset Inventory (Pre-Month 1) → Network Segmentation (Month 3)**: A complete and accurate inventory of all network-connected devices must be finalized so that segmentation rules do not inadvertently break critical clinical workflows.
3.  **Log Sourcing/Configuration (Month 4) → SIEM Deployment (Month 5)**: All clinical endpoints and servers must be configured to forward logs correctly before the centralized SIEM can effectively ingest and analyze data.

---

## Milestones

| Date | Milestone | Accomplishment | Success Indicator |
| :--- | :--- | :--- | :--- |
| **Month 1** | Foundation Established | Quick wins and policy formalization | 100% compliance with GPO settings |
| **Month 2** | Perimeter Secured | MFA active on all critical access points | 0 successful unauthorized VPN logins |
| **Month 4** | Blast Radius Contained | Clinical and Medical zones segmented | 0 lateral movement alerts across zones |
| **Month 6** | Operational Resilience | Full program validation and audit | Pass internal maturity assessment |

---

## Risk to Timeline & Contingency Plans

1.  **Risk: Clinical Workflow Disruption**
    *   *Cause*: Aggressive segmentation rules accidentally blocking critical communication between medical devices and EHR servers.
    *   *Contingency*: Implement "Monitor Mode" (logging without blocking) for 14 days prior to enforcing hard firewall blocks to identify and whitelist critical traffic paths.
2.  **Risk: Resource Scarcity**
    *   *Cause*: Competing operational priorities (e.g., unexpected EHR system upgrades) pulling IT staff away from security project milestones.
    *   *Contingency*: Re-prioritize "Security First" hours into the weekly IT schedule, ensuring at least 20% of staff capacity is locked for security-specific implementation tasks regardless of other tickets.

---
