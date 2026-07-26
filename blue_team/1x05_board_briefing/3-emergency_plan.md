# The 72-Hour Emergency Response Plan

## Tier 1 - Tonight (0-12 hours)

* **Action 1:** Physically disconnect the backup Network Attached Storage (`NAS-01`) from the production network switches to establish an air-gap and prevent pre-encryption deletion via `vssadmin` or file corruption.
  * **Phase Blocked:** Phase 5 (Backup Destruction)
  * **Owner:** Sarah Park (and 2 IT staff)
  * **Prerequisites:** Physical access to the server room and identification of backup switch ports.
  * **Risk of Action:** Temporary inability to run scheduled overnight incremental backups; minor logging alerts.
  * **Risk of Inaction:** Attackers remotely access network-attached backup shares, delete shadow copies, and destroy backup repositories, eliminating recovery options.

* **Action 2:** Revoke all active VPN sessions and force immediate password and token resets for all administrative and remote accounts on the FortiGate firewall.
  * **Phase Blocked:** Phase 2 (Internal Reconnaissance)
  * **Owner:** Sarah Park
  * **Prerequisites:** Administrative access to the FortiGate management console.
  * **Risk of Action:** Brief user lockout and temporary disruption for active after-hours remote clinical/administrative staff.
  * **Risk of Inaction:** Attackers leverage stolen or cached memory session tokens to maintain persistent remote access and map internal subnets.

* **Action 3:** Implement emergency egress firewall rules blocking outbound traffic to known Tor entry nodes, mega.nz, and unapproved external cloud storage utilities (`Rclone`).
  * **Phase Blocked:** Phase 4 (Data Exfiltration)
  * **Owner:** Sarah Park
  * **Prerequisites:** FortiGate firewall rule modification privileges.
  * **Risk of Action:** Potential blocking of legitimate third-party cloud services if wildcard rules are too broad.
  * **Risk of Inaction:** Attackers silently exfiltrate 15-65 GB of sensitive patient EMR and financial records via encrypted tunneling tools.

---

## Tier 2 - Tomorrow (12-36 hours)

* **Action 1:** Secure emergency Board approval to disburse $2,400 for immediate FortiGate support contract renewal, download firmware patch `7.0.14`, and execute a scheduled emergency maintenance window to patch `CVE-2023-27997`.
  * **Phase Blocked:** Phase 1 (Initial Access)
  * **Owner:** CISO / Lead Strategist & Board of Directors
  * **Prerequisites:** Emergency Board quorum and financial sign-off.
  * **Risk of Action:** Brief downtime (10-15 minutes) of the perimeter VPN gateway during reboot.
  * **Risk of Inaction:** Firewall remains directly exploitable via public heap buffer overflow exploit code, allowing unauthenticated remote code execution.

* **Action 2:** Deploy temporary endpoint isolation scripts and verify signature updates across all critical clinical workstations and servers using existing EDR/antivirus management tools.
  * **Phase Blocked:** Phase 6 (Ransomware Deployment)
  * **Owner:** Sarah Park (2 IT staff)
  * **Prerequisites:** Functional management console access for endpoint security agents.
  * **Risk of Action:** False positive quarantines on legacy clinical software applications requiring quick administrative overrides.
  * **Risk of Inaction:** Unmitigated propagation of modified BlackSuit ransomware payloads via GPO or local script execution across endpoints.

* **Action 3:** Issue an urgent executive communication freeze and phishing/vishing awareness alert to all leadership and staff detailing Crimson Tide social engineering and direct phone coercion tactics.
  * **Phase Blocked:** Phase 7 (Extortion)
  * **Owner:** James (Operations / Executive Management)
  * **Prerequisites:** Executive leadership alignment and distribution list access.
  * **Risk of Action:** Heightened anxiety among staff or minor confusion regarding official communication channels.
  * **Risk of Inaction:** Executives fall victim to direct phone calls or targeted emails, leading to premature panic, unverified ransom negotiations, or data leaks.

---

## Tier 3 - This Week (36-72 hours)

* **Action 1:** Begin phased network switch configuration changes and internal VLAN creation to isolate critical EMR database servers (`DB-EMR-01`) from general user subnets.
  * **Phase Blocked:** Phase 3 (Lateral Movement)
  * **Owner:** Sarah Park (with external network vendor support)
  * **Prerequisites:** Maintenance window scheduling and configuration validation (2-3 days minimum setup).
  * **Risk of Action:** Potential interruption of internal application communication if firewall rules or VLAN tags are misconfigured.
  * **Risk of Inaction:** Flat network architecture permits unrestricted east-west traversal via RDP, SSH, and Kerberoasting.

* **Action 2:** Schedule and execute Active Directory Kerberos policy updates to disable legacy RC4-HMAC encryption downgrade paths during a controlled low-traffic maintenance window.
  * **Phase Blocked:** Phase 3 (Lateral Movement)
  * **Owner:** Sarah Park & IT Staff
  * **Prerequisites:** Thorough dependency mapping of legacy applications relying on RC4.
  * **Risk of Action:** Risk of breaking legacy authentication for older medical devices or clinical software still dependent on RC4.
  * **Risk of Inaction:** Attackers perform Kerberoasting attacks against domain service principal names to extract and crack administrative ticket hashes.

* **Action 3:** Establish an out-of-band, offline secondary backup verification routine and engage external incident response retainers for continuous 24/7 threat hunting.
  * **Phase Blocked:** Phase 5 & Phase 6 (Backup Destruction & Deployment)
  * **Owner:** You (CISO) & External Vendor
  * **Prerequisites:** Vendor contract finalization and resource allocation.
  * **Risk of Action:** Additional financial expenditure and operational friction.
  * **Risk of Inaction:** Lack of forensic visibility and inability to verify data integrity post-incident.

---

## Resource Conflict Assessment

### Identification of Conflicts
1. **Personnel Bottleneck (Sarah Park):** Sarah is designated as the primary technical lead across Tier 1 (session revocation, firewall egress rules), Tier 2 (endpoint deployment oversight), and Tier 3 (VLAN/switch segmentation and AD Kerberos changes). Furthermore, she only has 2 IT staff available. Attempting to execute firewall rule updates, endpoint checks, and physical server work simultaneously creates an acute operational bottleneck.
2. **System Contention (FortiGate Firewall):** Tier 1 requires immediate session termination and egress rule modification on the FortiGate, while Tier 2 requires firmware patching (`7.0.14`) on the exact same device within 24 hours. Performing these concurrent actions without proper sequencing risks administrative lockouts or configuration corruption.

### Resolution Strategy
* **Staggered Sequencing:** Sequence Sarah's workload strictly by urgency. Tonight (Tier 0-12h), Sarah and her 2 staff focus entirely on the physical air-gapping of `NAS-01` and emergency FortiGate session termination. Tomorrow (Tier 12-36h), once emergency Board funds are cleared, Sarah delegates endpoint agent verification to her 2 staff members while focusing herself on the FortiGate support renewal and firmware patch window.
* **Task Delegation & External Support:** Offload complex switch VLAN configurations and network segmentation (Tier 3) to the external network vendor rather than burdening internal IT staff, allowing Sarah and her team to concentrate purely on endpoint security and identity hardening.
