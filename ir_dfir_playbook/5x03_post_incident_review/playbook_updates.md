# Playbook Updates: IR-2026-0414-01

### Change PB-UPD-001
**Playbook:** playbook_credential_exposure.yaml  
**Section:** applies_to.triggers  
**Gap closed:** GAP-002  
**Finding reference:** control_effectiveness.yaml phase 2  
**Before:**  
```yaml
triggers:  
  - Alert: credential submitted to external domain  
```  
**After:**  
```yaml
triggers:  
  - Alert: credential submitted to external domain  
  - Alert: VPN authentication from country not seen for this account in 30 days  
  - Alert: impossible-travel detected on account (two logins from geographically inconsistent IPs within 2 hours)  
```  
**Reason:** The incident entry point was a foreign-IP VPN login that matched no existing trigger; this gap allowed the intrusion to proceed for over eight hours without a playbook activation.  

---

### Change PB-UPD-002
**Playbook:** playbook_credential_exposure.yaml  
**Section:** containment.scope_expansion  
**Gap closed:** GAP-009  
**Finding reference:** control_effectiveness.yaml phase 6  
**Before:**  
```yaml
containment:  
  steps:  
    - Reset password for primary compromised account.  
    - Isolate host where initial compromise occurred.  
```  
**After:**  
```yaml
containment:  
  steps:  
    - Reset password for primary compromised account.  
    - Isolate host where initial compromise occurred.  
    - If lateral movement or Pass-the-Ticket (T1550.003) is identified:  
        1. Perform Active Directory query for all service tickets (TGS) requested by the compromised identity in the last 24 hours.  
        2. Identify all target endpoints/IPs accessed via those tickets.  
        3. Expand isolation scope immediately to include all secondary targets in the blast radius.  
```  
**Reason:** The playbook had no structured step for expanding containment to newly identified hosts when Pass-the-Ticket indicators surfaced, allowing lateral movement to PHI repositories without immediate isolation.  

---

### Change PB-UPD-003
**Playbook:** playbook_credential_exposure.yaml  
**Section:** remediation.kerberos_remediation  
**Gap closed:** GAP-007, GAP-008  
**Finding reference:** control_effectiveness.yaml phase 5  
**Before:**  
```yaml
remediation:  
  steps:  
    - Reset compromised user account password in Active Directory.  
    - Revoke active user sessions.  
```  
**After:**  
```yaml
remediation:  
  steps:  
    - Reset compromised user account password in Active Directory.  
    - Revoke active user sessions.  
    - If Pass-the-Ticket or LSASS credential extraction is confirmed:  
        1. Initiate a double-reset of the Active Directory krbtgt account password (with a 10-hour interval between resets to account for Ticket Granting Ticket lifespan).  
        2. Force Kerberos ticket invalidation across all Domain Controllers.  
```  
**Reason:** The original playbook said "reset compromised account password" but did not specify the krbtgt rotation required to invalidate forged Kerberos tickets, leaving the domain vulnerable to persistence via stolen tickets.  

---

### Change PB-UPD-004
**Playbook:** playbook_credential_exposure.yaml  
**Section:** decision_tree.regulatory_assessment  
**Gap closed:** GAP-010  
**Finding reference:** control_effectiveness.yaml phase 6  
**Before:**  
```yaml
decision_tree:  
  - Check if internal policy or PII was impacted. Notify legal if needed.  
```  
**After:**  
```yaml
decision_tree:  
  - Check if internal policy or PII was impacted.  
  - If electronic Protected Health Information (ePHI) systems or databases are within the blast radius:  
      1. Initiate HIPAA Breach Notification Rule 4-Factor Risk Assessment immediately:  
          a. Nature and extent of ePHI involved (identifiers, clinical data).  
          b. Unauthorized person who used/received the ePHI.  
          c. Whether ePHI was actually viewed or acquired.  
          d. Extent to which risk has been mitigated.  
      2. Escalate findings immediately to the Privacy Officer and Legal Counsel.  
```  
**Reason:** The original playbook had no branch for clinical system involvement, delaying necessary compliance and legal workflows when ePHI systems were impacted.  