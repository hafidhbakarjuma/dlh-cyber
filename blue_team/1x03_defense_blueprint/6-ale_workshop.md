# ALE Workshop: MedDefense Risk Prioritization

## Executive Summary
This workshop converts identified security gaps and threats into quantitative ALE (Annualized Loss Expectancy) values to drive data-informed investment.

---

### Risk 1: VPN Compromise
* **Risk**: VPN Credential Theft leading to network-wide access
* **Source**: GAP-015, VPN exposure, External Attacker
* **Asset**: Internal Network (10.10.0.0/16)
* **AV**: $1,200,000 (Recovery: 200k + Downtime: 400k + Penalty: 200k + Reputation: 400k)
* **EF**: 100% (Full network access allows total compromise)
* **SLE**: $1,200,000
* **ARO**: 0.33 (1 in 3 years)
* **ALE**: $400,000
* **Proposed Control**: Multi-Factor Authentication (MFA)
* **Control Annual Cost**: $15,000
* **Estimated ALE After Control**: $80,000 (ARO reduced to 0.06)
* **Net Benefit**: $305,000

### Risk 2: Insider Data Theft (Negligent)
* **Risk**: Negligent staff mishandling sensitive patient data
* **Source**: GAP-007, Missing training, Insider
* **Asset**: Clinical Workstations
* **AV**: $120,000 (Investigation: 30k + Containment: 25k + Remediation: 40k + Reporting: 25k)
* **EF**: 100%
* **SLE**: $120,000
* **ARO**: 2.0 (Incidents per year)
* **ALE**: $240,000
* **Proposed Control**: Security Awareness Training
* **Control Annual Cost**: $10,000
* **Estimated ALE After Control**: $120,000 (ARO reduced to 1.0)
* **Net Benefit**: $110,000

### Risk 3: Ransomware (EHR)
* **Risk**: Ransomware encrypts primary EHR system
* **Source**: GAP-010, Backup weakness, BlackReef
* **Asset**: ehr-srv-01
* **AV**: $770,000 (Recovery: 100k + Downtime: 320k + Penalty: 150k + Reputation: 200k)
* **EF**: 90%
* **SLE**: $693,000
* **ARO**: 0.25 (1 in 4 years)
* **ALE**: $173,250
* **Proposed Control**: Immutable Backups
* **Control Annual Cost**: $25,000
* **Estimated ALE After Control**: $34,650 (EF reduced to 0.2)
* **Net Benefit**: $113,600

### Risk 4: Patient Data Exfiltration
* **Risk**: SQL Injection leading to exfiltration of 50k records
* **Source**: GAP-017, Vulnerable web apps, External attacker
* **Asset**: Patient Portal
* **AV**: $750,000 (Notification: 50k + Legal: 200k + Attrition: 500k)
* **EF**: 80%
* **SLE**: $600,000
* **ARO**: 0.2 (1 in 5 years)
* **ALE**: $120,000
* **Proposed Control**: WAF & Patch Management
* **Control Annual Cost**: $30,000
* **Estimated ALE After Control**: $24,000 (ARO reduced to 0.04)
* **Net Benefit**: $66,000

### Risk 5: Medical Device Patient Safety Incident
* **Risk**: Compromised infusion pump causing patient harm
* **Source**: GAP-001, Weak device security, Opportunistic attacker
* **Asset**: Infusion Pumps (7 units)
* **AV**: $2,250,000 (Liability: 2M + FDA: 150k + Disruption: 100k)
* **EF**: 50%
* **SLE**: $1,125,000
* **ARO**: 0.02 (1 in 50 years)
* **ALE**: $22,500
* **Proposed Control**: Network Segmentation
* **Control Annual Cost**: $20,000
* **Estimated ALE After Control**: $4,500 (ARO reduced to 0.004)
* **Net Benefit**: -$2,000

---

### Risk Prioritization Table

| Priority | Risk | ALE Before | Net Benefit |
| :--- | :--- | :---: | :---: |
| 1 | VPN Compromise | $400,000 | $305,000 |
| 2 | Insider Data Theft | $240,000 | $110,000 |
| 3 | Ransomware (EHR) | $173,250 | $113,600 |
| 4 | Data Exfiltration | $120,000 | $66,000 |
| 5 | Medical Device Safety | $22,500 | -$2,000 |
