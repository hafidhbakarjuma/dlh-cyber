# MedDefense Health Systems — The Legacy Dilemma
## Compensating Control Strategy: MRI Control Workstation (Windows XP Embedded)

**Prepared by:** Junior Security Analyst
**Prepared for:** James Chen, Deputy CISO
**Subject:** Siemens MAGNETOM MRI scanner, Radiology department, MedDefense Central
**Constraint:** Cannot patch, upgrade OS, replace device, or disconnect from network

---

## 1. Risk Analysis

This single workstation represents a risk to the entire MedDefense network, not just Radiology, because Windows XP has received no security patches since April 2014 — over a decade of publicly known, permanently unfixable vulnerabilities, including SMB-based remote code execution flaws (the same class of vulnerability exploited by WannaCry in 2017, which crippled hospital systems worldwide partly through legacy Windows devices exactly like this one). Because the MRI workstation currently sits on the same flat VLAN as general hospital workstations, it is not isolated from routine hospital traffic in either direction: any ordinary workstation compromised via phishing or a browser exploit could pivot laterally to attack the MRI directly, and conversely, if the MRI itself is compromised first, it becomes a permanent, unpatchable foothold from which an attacker can reach the EHR, billing, and domain controller infrastructure identified elsewhere in this assessment. Unlike every other unpatched asset in the environment, this one can never be brought current — meaning any vulnerability discovered against Windows XP from this point forward remains exploitable indefinitely, for as long as the device remains in clinical service (potentially six more years). The risk is therefore not contained to Radiology; it is a standing, permanent entry point into the broader network for as long as the current architecture persists.

---

## 2. Compensating Control Strategy

---

**Control 1: Isolated VLAN with Strict Access Control List (ACL)**
- **Description:** Place the MRI workstation on its own dedicated VLAN, separate from all general hospital workstations and other clinical devices. Configure firewall rules (leveraging the existing FortiGate 100F) to permit only the specific traffic required for clinical function — DICOM communication to the PACS server on its defined port(s) — and deny everything else by default, including internet access, SMB/file-sharing protocols, and any peer-to-peer traffic with other workstations.
- **Classification:** Technical / Compensating
- **Risk Reduction:** This directly substitutes for the infeasible ideal control (patching) by containing the blast radius instead of fixing the underlying vulnerability. Even if the OS remains permanently exploitable, an attacker on the general hospital network can no longer reach the MRI directly, and a compromised MRI can no longer reach anything beyond the PACS server it is explicitly permitted to talk to.
- **Limitations / Residual Risk:** Does not eliminate the vulnerability itself — the MRI remains exploitable by anyone who does gain access to its VLAN (e.g., via the PACS server itself, if that system is later compromised). Segmentation quality depends entirely on ACL discipline being maintained over time; a future "temporary" rule opened for troubleshooting and never closed would silently undo this control.

---

**Control 2: Network Intrusion Prevention with Legacy-Exploit Signatures ("Virtual Patching")**
- **Description:** Deploy IPS functionality (available on the existing FortiGate platform) at the boundary of the new isolated VLAN, configured with signatures specifically targeting known Windows XP-era exploits (e.g., SMB/RCE exploit patterns). Malicious traffic matching these patterns is blocked at the network layer before it ever reaches the workstation.
- **Classification:** Technical / Preventive
- **Risk Reduction:** Provides a network-layer substitute for the missing host-based security patches — commonly called "virtual patching" in industry practice. It reduces exposure to the most dangerous and well-documented exploit classes without touching the certified OS image.
- **Limitations / Residual Risk:** Only effective against known, signature-matched attack patterns; a novel or customized exploit targeting the same underlying vulnerability could still bypass it. Requires ongoing signature maintenance, which itself needs to be assigned as an owned, recurring task rather than a one-time setup.

---

**Control 3: Dedicated Logging and Alerting on Segment Traffic**
- **Description:** All traffic to and from the isolated MRI VLAN is logged in full (not just summary/utm-level logging), with alerting configured for any connection attempt outside the expected PACS communication pattern — including any attempt to reach the general hospital network, the internet, or any port/protocol outside the defined DICOM traffic baseline.
- **Classification:** Technical / Detective
- **Risk Reduction:** Because the device can never be fully secured, early detection of anomalous behavior becomes the primary way to limit dwell time if a compromise does occur — directly addressing the pattern already seen with the billing-srv-01 cryptominer, which persisted undetected for roughly two weeks under the current lack of centralized monitoring.
- **Limitations / Residual Risk:** Detective only — this control does not prevent compromise, it shortens the time to notice one, and only if someone is actually watching the alerts. Given the current absence of any centralized log correlation or alerting capability (identified as Gap G-004), this control depends on that broader capability being built or on a manual review process being explicitly assigned.

---

**Control 4: Documented Risk Acceptance and Annual Compensating Control Review (Administrative)**
- **Description:** A formal, signed-off policy document specific to this device, acknowledging the permanent, unpatchable nature of the risk, defining the compensating controls in place, assigning an owner responsible for their upkeep, and mandating an annual (at minimum) review to confirm the controls remain correctly configured and effective. Includes a defined point of contact for tracking manufacturer/FDA guidance on the device's end-of-life status.
- **Classification:** Administrative / Compensating
- **Risk Reduction:** Ensures this risk is a formally tracked, owned, and periodically re-validated organizational decision rather than an unaddressed item sitting in a folder for six months, as it has been. This is itself a compensating control in the administrative domain — governance substituting for the inability to apply the ideal technical fix.
- **Limitations / Residual Risk:** A policy document does not reduce technical risk on its own; it only works if paired with the technical/physical controls above and if the review cadence is genuinely enforced rather than becoming another item that slips.

---

**Control 5: Restricted Physical Access to the Control Room (Physical)**
- **Description:** Ensure the MRI control workstation is only physically accessible from a restricted, access-controlled space (not a shared/open area), preventing casual physical interaction such as inserting removable media, connecting unauthorized devices, or directly tampering with the machine.
- **Classification:** Physical / Preventive
- **Risk Reduction:** Windows XP-era systems are also vulnerable to local infection vectors (e.g., malware delivered via USB media, historically a proven attack path against isolated industrial/medical control systems). Restricting physical access closes an entry point that network-layer controls cannot address at all.
- **Limitations / Residual Risk:** Only effective against opportunistic or casual physical access; does not stop a determined insider with legitimate physical access to the room. Depends on the existing badge system being more granular here than the generic, hospital-wide badge already flagged as a weakness elsewhere in this assessment.

---

## 3. Implementation Priority

If only one control could be implemented immediately, it should be **Control 1: Isolated VLAN with Strict Access Control List.**

**Justification:** Network segmentation addresses the single architectural flaw that makes this device an organization-wide risk rather than a contained departmental one — the fact that it currently shares a flat network with everything else. It is achievable using infrastructure MedDefense already owns (the FortiGate 100F), meaning it requires no new budget approval, unlike a signature-based IPS subscription or a device replacement. Unlike Control 2 (IPS), which only stops attacks matching known signatures, segmentation is signature-agnostic — it reduces exposure to known and unknown exploits alike, simply by removing the reachability that makes exploitation possible in the first place. It also directly closes Gap G-005 (flat network, no segmentation) already identified as a systemic weakness affecting far more than just this device — meaning this one control produces value beyond the MRI alone, by establishing a segmentation pattern that could later be extended to other medical IoT devices facing the same underlying exposure. Detective and administrative controls matter, but they only reduce how much damage or how long an incident lasts — segmentation is the one control here that meaningfully reduces the likelihood of compromise actually reaching the device to begin with.
