# Control Selection and Justification

This document maps security controls to the risks identified in Task 10, ensuring alignment with CIS Controls and NIST CSF frameworks while maintaining budget compliance.

## Control Selections

### RISK-001: Ransomware destroys production and backup together
* **Selected Control**: Offsite backup replication (Immutable storage)[cite: 3]
* **CIS Control Mapping**: 11.4 (Protect Data)[cite: 3]
* **NIST CSF Mapping**: PR.IP-1[cite: 3]
* **Control Type**: Corrective[cite: 3]
* **Control Category**: Technical[cite: 3]
* **Implementation Cost**: $20,000[cite: 3]
* **Expected Risk Reduction**: $421,470 (ALE reduction)[cite: 3]
* **Dependencies**: None (Can be implemented immediately)[cite: 3]

### RISK-002: VPN credential theft enables network breach
* **Selected Control**: Multi-Factor Authentication (MFA)[cite: 3]
* **CIS Control Mapping**: 6.1 (Access Control Management)[cite: 3]
* **NIST CSF Mapping**: PR.AC-7[cite: 3]
* **Control Type**: Preventive[cite: 3]
* **Control Category**: Technical[cite: 3]
* **Implementation Cost**: $15,000[cite: 3]
* **Expected Risk Reduction**: $321,900 (ALE reduction)[cite: 3]
* **Dependencies**: None[cite: 3]

### RISK-003: Ransomware encrypts EHR via flat network
* **Selected Control**: Network Segmentation (VLANs)[cite: 3]
* **CIS Control Mapping**: 12.1 (Network Infrastructure Management)[cite: 3]
* **NIST CSF Mapping**: PR.AC-5[cite: 3]
* **Control Type**: Preventive[cite: 3]
* **Control Category**: Technical[cite: 3]
* **Implementation Cost**: $30,000[cite: 3]
* **Expected Risk Reduction**: $259,560 (ALE reduction)[cite: 3]
* **Dependencies**: Inventory of critical assets (requires asset registry)[cite: 3]

### RISK-005: Malware runs undetected for weeks, no logging
* **Selected Control**: SIEM deployment (Wazuh)[cite: 3]
* **CIS Control Mapping**: 13.1 (Centralized Log Management)[cite: 3]
* **NIST CSF Mapping**: DE.AE-3[cite: 3]
* **Control Type**: Detective[cite: 3]
* **Control Category**: Operational[cite: 3]
* **Implementation Cost**: $20,000[cite: 3]
* **Expected Risk Reduction**: $53,400 (ALE reduction)[cite: 3]
* **Dependencies**: Log sources must be configured on all endpoints[cite: 3]

### RISK-006: Infusion pumps compromised via default credentials
* **Selected Control**: Network Segmentation + Credential Hardening[cite: 3]
* **CIS Control Mapping**: 12.1 (Network Infrastructure Management)[cite: 3]
* **NIST CSF Mapping**: PR.AC-5[cite: 3]
* **Control Type**: Preventive[cite: 3]
* **Control Category**: Technical[cite: 3]
* **Implementation Cost**: Shared with Segmentation ($0 additional)[cite: 3]
* **Expected Risk Reduction**: $46,575 (ALE reduction)[cite: 3]
* **Dependencies**: Network Segmentation (RISK-003)[cite: 3]

### RISK-007: Secondary domain controller has no backup
* **Selected Control**: Backup Schedule Extension[cite: 3]
* **CIS Control Mapping**: 11.2 (Manage Backups)[cite: 3]
* **NIST CSF Mapping**: PR.IP-1[cite: 3]
* **Control Type**: Corrective[cite: 3]
* **Control Category**: Administrative[cite: 3]
* **Implementation Cost**: $2,500 (Labor)[cite: 3]
* **Expected Risk Reduction**: High (Full recovery capability)[cite: 3]
* **Dependencies**: Storage capacity verification[cite: 3]

### RISK-008: PACS server excluded from backup
* **Selected Control**: Backup Schedule Extension[cite: 3]
* **CIS Control Mapping**: 11.2 (Manage Backups)[cite: 3]
* **NIST CSF Mapping**: PR.IP-1[cite: 3]
* **Control Type**: Corrective[cite: 3]
* **Control Category**: Administrative[cite: 3]
* **Implementation Cost**: $2,500 (Labor)[cite: 3]
* **Expected Risk Reduction**: High (Data loss prevention)[cite: 3]
* **Dependencies**: Backup infrastructure availability[cite: 3]

### RISK-009: Shared PACS login removes accountability
* **Selected Control**: Individual Account Provisioning[cite: 3]
* **CIS Control Mapping**: 5.1 (Establish and Maintain User Accounts)[cite: 3]
* **NIST CSF Mapping**: PR.AC-1[cite: 3]
* **Control Type**: Preventive[cite: 3]
* **Control Category**: Administrative[cite: 3]
* **Implementation Cost**: $1,000 (Labor)[cite: 3]
* **Expected Risk Reduction**: Reduced insider threat surface[cite: 3]
* **Dependencies**: Central Identity Provider access[cite: 3]

### RISK-010: Network closet has weak badge access, no camera
* **Selected Control**: Physical Access Control & Camera Installation[cite: 3]
* **CIS Control Mapping**: 1.1 (Establish and Maintain Physical Security)[cite: 3]
* **NIST CSF Mapping**: PR.AC-2[cite: 3]
* **Control Type**: Preventive[cite: 3]
* **Control Category**: Physical[cite: 3]
* **Implementation Cost**: $5,000[cite: 3]
* **Expected Risk Reduction**: Reduced physical tampering risk[cite: 3]
* **Dependencies**: Facilities approval[cite: 3]

---

## Control Dependency Map

```text
[Asset Inventory] 
      |
      v
[Network Segmentation (RISK-003)] ---> [Device Isolation (RISK-006)]
      |
      v
[SIEM (RISK-005)] 
      |
      v
[24/7 Monitoring (Future)]
