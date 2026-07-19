# 12. The Legacy Systems Assessment

This report evaluates the risk profile of MedDefense's three end-of-life (EOL) systems, focusing on the categorical difference between "unpatched" and "permanently vulnerable" assets.

---

## 1. Windows XP SP3 (10.10.1.70, MRI Workstation)
* **EOL Research:** A search for CVEs affecting Windows XP in the last two years yields hundreds of results; while many are generic Windows vulnerabilities, the OS is fundamentally unable to handle modern security requirements. Two critical examples: CVE-2024-30082 (Kernel RCE) and various RDP-related flaws.
* **Permanent Exposure:** EOL is fundamentally different because there is no path to remediation. Even if you "patch" one hole, the underlying architecture is incompatible with modern security, meaning the system remains a permanent liability that cannot be secured through software updates alone.
* **Scan Findings:** Finding 004 (Multiple RCEs including EternalBlue and BlueKeep). These are directly exploitable because the OS is too old to support modern SMB or RDP security protocols.
* **Compensating Controls:** Proposed controls include network isolation/segmentation. These are essential but likely insufficient given the device's need to communicate with clinical workstations and the PACS server. **Recommended additional controls:** Deploy a host-based firewall and strictly disable all unnecessary services (SMB, RDP) if not required for MRI functionality.
* **Business Decision (Priority Rank: 1 - Highest):** This system must be migrated first. It is an MRI control workstation (Clinical/Patient Safety impact) with weaponized RCEs that could easily lead to network-wide ransomware propagation.

---

## 2. Windows Server 2012 R2 (10.10.2.31, Print Server)
* **EOL Research:** NVD search for Windows Server 2012 R2 reveals significant findings in the last two years, including CVE-2024-30044 (Kernel LPE) and PrintNightmare-related variants (CVE-2023-23397).
* **Permanent Exposure:** Because the vendor no longer releases patches for this specific OS version, any new vulnerability discovered in the Windows Server 2012 codebase is a permanent opening for attackers that the internal team cannot fix.
* **Scan Findings:** Finding 008 (PrintNightmare/CVE-2021-34527). This is directly exploitable due to the lack of security updates for the Print Spooler service.
* **Compensating Controls:** Current controls are missing. **Recommended controls:** Move the print service to a modern OS, or apply strict ACLs and disable the Print Spooler on all non-essential servers.
* **Business Decision (Priority Rank: 2):** Important, but less critical than the MRI workstation. Print services can be mitigated by offloading to modern servers or disabling unnecessary print features until a full migration occurs.

---

## 3. Ubuntu 18.04 LTS (10.10.2.15, Billing Server)
* **EOL Research:** NVD search reveals numerous critical CVEs from the last two years applicable to the underlying packages, such as CVE-2024-21626 (runc container escape) and various glibc vulnerabilities.
* **Permanent Exposure:** Being EOL means this server is accumulating "technical security debt." Every month that passes without updates makes it more accessible to automated scanners targeting these specific outdated library versions.
* **Scan Findings:** Finding 001 (mod_lua RCE), Finding 002 (Privilege Escalation), Finding 006 (MySQL exposure), Finding 009 (SSH password auth), Finding 011 (EOL status), Finding 026 (Kernel vulnerabilities). The EOL status is the root cause preventing the remediation of Findings 001, 002, and 026.
* **Compensating Controls:** No effective controls currently exist. **Recommended controls:** Immediate enrollment in Ubuntu Pro for ESM (Extended Security Maintenance) as a temporary stop-gap, followed by urgent migration to a supported LTS version.
* **Business Decision (Priority Rank: 3 - Lowest of the three):** While financially critical, this server is less likely to serve as a worm-based "patient zero" for clinical network collapse compared to the XP MRI workstation.

---

## Conclusion: Business Justification for Migration
If MedDefense can only migrate one system in the next quarter, the **Windows XP MRI Workstation (10.10.1.70)** must take precedence. It represents the highest risk of clinical disruption and network-wide compromise due to the presence of weaponized, wormable RCE exploits (EternalBlue/BlueKeep) sitting on a flat clinical network.
