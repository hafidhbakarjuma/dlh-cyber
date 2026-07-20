# The Budget Game: Final Resource Allocation

## Part 1: Selection
We have allocated the $120,000 budget to maximize Net Value while ensuring critical coverage for the highest-priority threats[cite: 3].

| Status | Control | Cost | Reasoning |
| :--- | :--- | :--- | :--- |
| **Funded** | MFA deployment | $15,000 | Highest ROI; essential for stopping primary entry vectors[cite: 3]. |
| **Funded** | Network segmentation | $30,000 | Critical for containing ransomware lateral movement[cite: 3]. |
| **Funded** | Offsite backup | $20,000 | Mandatory for ransomware recovery[cite: 3]. |
| **Funded** | EDR upgrade | $25,000 | Vital for endpoint visibility and threat response[cite: 3]. |
| **Funded** | Wazuh SIEM | $20,000 | Cost-effective logging and operational insight[cite: 3]. |
| **Deferred** | Westside firewall | $10,000 | Lower impact compared to enterprise-wide controls; defer to FY27[cite: 3]. |
| **Rejected** | Outsourced 24/7 SOC | $80,000 | Cost exceeds risk reduction value; not sustainable[cite: 3]. |
| **Rejected** | Full device isolation | $40,000 | Excessive cost; risk managed through segmentation[cite: 3]. |

* **Total Spend**: $110,000[cite: 3]
* **Budget Remaining**: $10,000[cite: 3]

---

## Part 2: Opportunity Cost
By deferring the **Westside firewall**, MedDefense accepts an estimated **$15,000** in annual risk exposure[cite: 3]. While we remain vulnerable to localized breaches at that specific clinic, the enterprise-wide controls (MFA, Segmentation) mitigate the primary pathways for that threat actor to reach sensitive data[cite: 3].

---

## Part 3: The Alternative
We considered an alternative allocation prioritizing the **Westside firewall** over the **Wazuh SIEM**[cite: 3].

* **Alternative Allocation**: MFA ($15k), Network Segmentation ($30k), Backup ($20k), EDR ($25k), Westside firewall ($10k)[cite: 3].
* **Total Cost**: $100,000[cite: 3]
* **Total ALE Reduction**: $703,000[cite: 3]
* **Primary Recommendation Reduction**: $728,000[cite: 3]

**Comparison**: The primary recommendation is superior, providing an additional **$25,000** in risk reduction[cite: 3]. The SIEM provides enterprise-wide visibility, whereas the firewall is limited to one location, making the primary recommendation the better strategic investment[cite: 3].
