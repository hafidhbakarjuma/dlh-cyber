# The Budget Game: Final Resource Allocation

## Part 1: Selection

We have successfully **funded** the optimal controls within our $120,000 budget to maximize Net Value while ensuring critical coverage for the highest-priority threats. Every chosen initiative is **funded** based on its return on investment and risk reduction capacity.

| Status | Control | Cost | Reasoning |
| :--- | :--- | :--- | :--- |
| **Funded** | MFA deployment | $15,000 | Highest ROI; essential for stopping primary entry vectors. |
| **Funded** | Network segmentation | $30,000 | Critical for containing ransomware lateral movement. |
| **Funded** | Offsite backup | $20,000 | Mandatory for ransomware recovery. |
| **Funded** | EDR upgrade | $25,000 | Vital for endpoint visibility and threat response. |
| **Funded** | Wazuh SIEM | $20,000 | Cost-effective logging and operational insight. |
| **Deferred** | Westside firewall | $10,000 | Lower impact compared to enterprise-wide controls; defer to FY27. |
| **Rejected** | Outsourced 24/7 SOC | $80,000 | Cost exceeds risk reduction value; not sustainable. |
| **Rejected** | Full device isolation | $40,000 | Excessive cost; risk managed through segmentation. |

Total Spend: $110,000  
Budget Remaining: $10,000  

---

## Part 2: Opportunity Cost

By deferring the Westside firewall, MedDefense accepts an estimated $15,000 in annual risk exposure. While we remain vulnerable to localized breaches at that specific clinic, the enterprise-wide controls (MFA, Segmentation) mitigate the primary pathways for that threat actor to reach sensitive data.

---

## Part 3: The Alternative

We considered an alternative allocation prioritizing the Westside firewall over the Wazuh SIEM.  
Alternative Allocation: MFA ($15k), Network Segmentation ($30k), Backup ($20k), EDR ($25k), Westside firewall ($10k).  
Total Cost: $100,000  
Total ALE Reduction: $703,000  
Primary Recommendation Reduction: $728,000  

Comparison: The primary recommendation is superior, providing an additional $25,000 in risk reduction. The SIEM provides enterprise-wide visibility, whereas the firewall is limited to one location, making the primary recommendation the better strategic investment.
