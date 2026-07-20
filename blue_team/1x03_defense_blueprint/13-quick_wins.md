# Quick Wins: Immediate Security Improvements

These five "quick wins" are designed to be implemented within 14 days using existing resources, requiring no additional budget.

### Quick Win #1: Disable Unused Default Accounts
* **Risk Addressed**: RISK-002 (VPN/Network access)
* **Action**: Audit the VPN and domain controller for inactive or default service accounts; disable any account not used within the last 90 days.
* **Owner**: IT Director (Sarah Park)
* **Timeline**: 2 Days
* **Cost**: $0 (Internal labor only)
* **Risk Reduction**: Disrupts the "Initial Access" phase of the cyber kill chain by removing easy-to-guess entry points.
* **Verification**: Review the Active Directory "Disabled Users" report to confirm the accounts are inactive.

### Quick Win #2: Enforce Screen Lock Policy
* **Risk Addressed**: RISK-004 (Insider data exposure)
* **Action**: Update Group Policy (GPO) to enforce an automatic screen lock on all workstations after 10 minutes of inactivity.
* **Owner**: IT Director (Sarah Park)
* **Timeline**: 3 Days
* **Cost**: $0 (Standard configuration)
* **Risk Reduction**: Disrupts the "Physical/Insider" threat path by preventing unauthorized access to unattended clinical workstations.
* **Verification**: Physically test a workstation by leaving it idle for 10 minutes to ensure it locks.

### Quick Win #3: Harden Guest Wi-Fi
* **Risk Addressed**: RISK-003 (Network segmentation)
* **Action**: Isolate the existing Guest Wi-Fi network onto a separate VLAN with no internal network routing access.
* **Owner**: IT Systems Administrator
* **Timeline**: 5 Days
* **Cost**: $0 (Network hardware configuration)
* **Risk Reduction**: Disrupts the "Lateral Movement" phase by preventing guest devices from scanning or accessing hospital servers.
* **Verification**: Attempt to ping an internal clinical server from a device connected to the Guest Wi-Fi.

### Quick Win #4: Secure Backup Air-Gap (Manual)
* **Risk Addressed**: RISK-001 (Ransomware/Backup destruction)
* **Action**: Configure the backup server to disconnect from the main domain during non-backup hours to prevent ransomware from reaching the backup repository.
* **Owner**: IT Systems Administrator
* **Timeline**: 4 Days
* **Cost**: $0 (Scripting/configuration)
* **Risk Reduction**: Disrupts the "Impact" phase of the kill chain by ensuring a clean, unencrypted recovery source exists.
* **Verification**: Check server logs to verify connectivity is severed during the specified "off" hours.

### Quick Win #5: Remove Local Administrator Rights
* **Risk Addressed**: RISK-006 (Device/Endpoint compromise)
* **Action**: Remove local administrator privileges from standard clinical staff user accounts via GPO.
* **Owner**: IT Systems Administrator
* **Timeline**: 7 Days
* **Cost**: $0 (Internal policy update)
* **Risk Reduction**: Disrupts "Privilege Escalation" by ensuring users cannot install malware that requires elevated system access.
* **Verification**: Attempt to install a test application on a standard workstation using a non-admin account.

---

## The Strategic Value of Quick Wins
Beyond the immediate reduction of risk, quick wins are vital for establishing security as a tangible, operational discipline rather than an abstract concept. In the first month of a security program, they serve as a powerful tool for building organizational credibility and trust between the Security team and clinical staff. By demonstrating visible, low-friction improvements, the security team shows that they understand the hospital's operational realities and are committed to protecting the environment without causing unnecessary disruption to patient care.
