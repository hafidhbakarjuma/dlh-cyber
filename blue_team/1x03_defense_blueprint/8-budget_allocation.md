# The Budget Game: Final Resource Allocation

## Part 1: The Selection

We have successfully **funded** the optimal set of controls within our **$120,000** budget ceiling to maximize Net Value while ensuring critical coverage for the highest-priority threats. Every initiative is explicitly categorized as **funded**, **deferred**, or **rejected** based on risk reduction capacity and ROI.

| Status | Control | Cost | Reasoning |
| :--- | :--- | :--- | :--- |
| **Funded** | MFA deployment | $15,000 | Highest ROI; essential for stopping primary credential-based entry vectors. |
| **Funded** | Network segmentation | $30,000 | Critical for containing lateral movement and breaking ransomware propagation. |
| **Funded** | Offsite backup | $20,000 | Mandatory for reliable ransomware recovery and data preservation. |
| **Funded** | EDR upgrade | $25,000 | Vital for deep endpoint visibility and rapid threat response. |
| **Funded** | Wazuh SIEM | $20,000 | Cost-effective log aggregation and centralized operational insight. |
| **Deferred** | Westside firewall | $10,000 | Lower impact compared to enterprise-wide controls; **deferred** to FY27. |
| **Rejected** | Outsourced 24/7 SOC | $80,000 | Cost exceeds total risk reduction value; **rejected** outright as unsustainable. |
| **Rejected** | Full device isolation | $40,000 | Excessive cost; **rejected** because risk is adequately managed through segmentation. |

* **Total spend**: $110,000
* **Budget remaining**: $10,000 (reserved for emergency technical contingencies)
* **Total budget limit**: $120,000

---

## Part 2: The Opportunity Cost

By **deferring** the Westside firewall, MedDefense accepts an estimated $15,000 in annual risk exposure. While we remain vulnerable to localized perimeter breaches at that specific clinic, our enterprise-wide controls (MFA, Segmentation) successfully mitigate the primary network pathways required for attackers to reach sensitive internal data systems.

---

## Part 3: The Alternative

We evaluated an alternative allocation prioritizing the Westside firewall over the Wazuh SIEM to test portfolio trade-offs:
* **Alternative Allocation**: MFA ($15k), Network Segmentation ($30k), Backup ($20k), EDR ($25k), Westside firewall ($10k).
* **Alternative Total Cost**: $100,000
* **Alternative Total ALE Reduction**: $703,000
* **Primary Recommendation ALE Reduction**: $728,000

**Comparison & Trade-off Analysis**: 
The primary recommendation is superior on paper, providing an additional $25,000 in risk reduction for a slightly higher overall spend. The Wazuh SIEM provides enterprise-wide visibility and behavioral log analysis across all segments, whereas the alternative firewall is constrained to a single physical location. However, dropping the SIEM in favor of the firewall trades broad operational visibility for localized perimeter hardening. We selected the primary recommendation because enterprise visibility yields a higher net reduction in systemic risk than localized firewall protection at this maturity stage.
