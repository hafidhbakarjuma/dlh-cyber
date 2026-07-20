# Cost-Benefit Analysis: Security Control Investments

The following evaluation analyzes eight proposed security controls using formal cost-benefit analysis[cite: 3]. A control is considered financially justified when the ALE reduction exceeds the total annual cost of the investment[cite: 3].

---

## Control Evaluations

### Control 1: MFA deployment
* **CIS Control Reference**: 6[cite: 3]
* **Annual Cost**: $15,000 (Labor for implementation/maintenance)[cite: 3]
* **Risk(s) Addressed**: VPN Credential Theft, Admin Account Compromise[cite: 3]
* **ALE Reduction**: $320,000[cite: 3]
* **Net Value**: $305,000[cite: 3]
* **Verdict**: Justified[cite: 3]
* **Recommendation**: Implement (Highest ROI control to mitigate primary entry vectors)[cite: 3]

### Control 2: Network segmentation
* **CIS Control Reference**: 12[cite: 3]
* **Annual Cost**: $30,000 (Licensing $10k + Labor $20k)[cite: 3]
* **Risk(s) Addressed**: Ransomware lateral movement, Medical device exposure[cite: 3]
* **ALE Reduction**: $150,000[cite: 3]
* **Net Value**: $120,000[cite: 3]
* **Verdict**: Justified[cite: 3]
* **Recommendation**: Implement (Critical for containing threats to segmented zones)[cite: 3]

### Control 3: Offsite backup
* **CIS Control Reference**: 11[cite: 3]
* **Annual Cost**: $20,000 (Cloud storage costs $15k + Labor $5k)[cite: 3]
* **Risk(s) Addressed**: Ransomware (EHR/Data loss)[cite: 3]
* **ALE Reduction**: $138,585[cite: 3]
* **Net Value**: $118,585[cite: 3]
* **Verdict**: Justified[cite: 3]
* **Recommendation**: Implement (Provides essential recovery path for ransomware events)[cite: 3]

### Control 4: EDR upgrade
* **CIS Control Reference**: 8[cite: 3]
* **Annual Cost**: $25,000 (Licensing $20k + Labor $5k)[cite: 3]
* **Risk(s) Addressed**: Endpoint compromise, Data exfiltration[cite: 3]
* **ALE Reduction**: $80,000[cite: 3]
* **Net Value**: $55,000[cite: 3]
* **Verdict**: Justified[cite: 3]
* **Recommendation**: Implement (Enhances visibility and automated threat response)[cite: 3]

### Control 5: Wazuh SIEM
* **CIS Control Reference**: 13[cite: 3]
* **Annual Cost**: $20,000 (Labor cost for deployment/tuning)[cite: 3]
* **Risk(s) Addressed**: Log visibility, Insider detection[cite: 3]
* **ALE Reduction**: $40,000[cite: 3]
* **Net Value**: $20,000[cite: 3]
* **Verdict**: Justified[cite: 3]
* **Recommendation**: Implement (Cost-effective log aggregation for operational oversight)[cite: 3]

### Control 6: Outsourced 24/7 SOC
* **CIS Control Reference**: 13[cite: 3]
* **Annual Cost**: $80,000 (Managed service fees)[cite: 3]
* **Risk(s) Addressed**: Delayed incident detection[cite: 3]
* **ALE Reduction**: $100,000[cite: 3]
* **Net Value**: $20,000[cite: 3]
* **Verdict**: Not Justified[cite: 3]
* **Recommendation**: Reject (Cost is too high relative to the limited risk reduction value; funds better allocated elsewhere)[cite: 3]

### Control 7: Westside firewall
* **CIS Control Reference**: 12[cite: 3]
* **Annual Cost**: $10,000 (Hardware $5k + Labor $5k)[cite: 3]
* **Risk(s) Addressed**: Localized network perimeter breach[cite: 3]
* **ALE Reduction**: $15,000[cite: 3]
* **Net Value**: $5,000[cite: 3]
* **Verdict**: Marginal[cite: 3]
* **Recommendation**: Defer (Value is minimal compared to the impact of enterprise-wide controls)[cite: 3]

### Control 8: Full device isolation
* **CIS Control Reference**: 12[cite: 3]
* **Annual Cost**: $40,000 (Maintenance/Hardware/Labor)[cite: 3]
* **Risk(s) Addressed**: Medical device safety incident[cite: 3]
* **ALE Reduction**: $20,000[cite: 3]
* **Net Value**: -$20,000[cite: 3]
* **Verdict**: Not Justified[cite: 3]
* **Recommendation**: Reject (Exceeds acceptable ROI threshold; risk is better managed through segmentation)[cite: 3]

---

## Cost-Benefit Summary Table

| Control | Annual Cost | Net Value | Verdict | Recommendation |
| :--- | :--- | :--- | :--- | :--- |
| MFA deployment | $15,000 | $305,000 | Justified | Implement |
| Network segmentation | $30,000 | $120,000 | Justified | Implement |
| Offsite backup | $20,000 | $118,585 | Justified | Implement |
| EDR upgrade | $25,000 | $55,000 | Justified | Implement |
| Wazuh SIEM | $20,000 | $20,000 | Justified | Implement |
| Outsourced 24/7 SOC | $80,000 | $20,000 | Not Justified | Reject |
| Westside firewall | $10,000 | $5,000 | Marginal | Defer |
| Full device isolation | $40,000 | -$20,000 | Not Justified | Reject |

### Budget Alignment
The total cost of all recommended "Implement" controls is **$110,000**, which falls within the **$120,000** annual budget allocation[cite: 3].
