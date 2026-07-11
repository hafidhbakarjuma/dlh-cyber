# MedDefense Health Systems — The Shadow Systems

**Prepared by:** Junior Security Analyst
**Prepared for:** James Chen, Deputy CISO
**Source:** Verbal disclosure from Mike Torres (Helpdesk Lead), cross-referenced against Asset Registry (Task 7) and Complete Control Matrix (Task 10)

---

## 1. Dr. Patel's Personal NAS (Cardiology)

### Risk Assessment
- **Sensitive data:** Cardiology research data, plugged directly into a hospital wall port. Depending on how the research is conducted, this may include identifiable or partially identifiable patient data tied to cardiac studies — placing it well within Restricted-classification territory (Task 9), even though nobody in IT or security currently knows what's actually stored on it.
- **Controls not covering it:** Not listed in the Asset Registry (Task 7) or Control Matrix (Task 10). Not covered by Sophos antivirus (personal, non-domain device). Not covered by the Veeam backup job (Task 4/10, C-010 — scope is limited to named IT-managed servers). Not subject to the AD password policy (C-012) since it isn't domain-joined. No logging or monitoring control in the registry applies to it. It sits on the same flat network as every other Central asset, so segmentation offers no containment either.
- **Worst-case scenario:** Consumer-grade NAS devices are a well-known ransomware target category; a compromise here could mean loss or exposure of patient-linked research data with zero prior visibility that the data existed outside official systems — meaning MedDefense could face a HIPAA breach notification obligation for data it didn't even know it was responsible for protecting.

### Recommended Response: **Migrate**
Dr. Patel's underlying need — faster storage than the official shared drive — is legitimate and should be solved, but a personal consumer NAS is not an acceptable long-term home for data that may be patient-linked, regardless of how well it might later be secured in place. Migrating this data to an approved, IT-managed storage system (with adequate performance provisioned to actually solve his original complaint) removes the device from the network entirely rather than attempting to retroactively secure a device never designed for this purpose. Simply legitimizing it in place would still leave MedDefense dependent on consumer-grade hardware for sensitive research data.

---

## 2. Marketing's Shared Google Drive (Personal Gmail-Linked)

### Risk Assessment
- **Sensitive data:** Media files and press communications — lower classification than patient data (Internal, per Task 9), but may include embargoed or pre-release press materials with real reputational and business impact if leaked or altered early.
- **Controls not covering it:** By definition, none of MedDefense's controls apply — the account is tied to an individual's personal Gmail identity, not an organizational one. The password policy (C-012), any future MFA requirement, and all logging/audit controls are structurally unable to reach an account MedDefense doesn't own.
- **Worst-case scenario:** If the employee who owns the personal account leaves, loses access, or has that personal account compromised (personal Gmail accounts typically lack the security hardening of managed enterprise accounts), MedDefense could lose access to its own marketing assets entirely, or have unreleased press communications leaked or tampered with before official publication — with no recourse, since the account was never the organization's to control.

### Recommended Response: **Migrate**
"Legitimize" is not actually available as an option here — an account tied to a personal Gmail identity cannot be brought under organizational governance by definition; ownership is external. The only viable path is moving these files to storage MedDefense already owns and already has controls for — the existing O365 environment (SharePoint/OneDrive), which is already in use organization-wide and eliminates the single-point-of-failure risk of the data living in someone's personal account.

---

## 3. Raspberry Pi Network Monitor (2nd Floor, Central)

### Risk Assessment
- **Sensitive data:** Unknown and potentially significant — if it was ever actually configured as a network monitor as Marcus intended, it may have captured network traffic, credentials, or other sensitive data during its operational period. Nobody currently knows its configuration, so this cannot be ruled out.
- **Controls not covering it:** Entirely absent from the Asset Registry and Control Matrix. No patch management, no credential rotation, no monitoring of the device itself — meaning the one device MedDefense has that was meant to provide detection capability is itself completely undetected and unmanaged.
- **Worst-case scenario:** This device shares the same risk profile as UNKNOWN-01 (Task 7/8) — an unmanaged device with unknown credentials, sitting on the flat internal network, untouched since the only two people who understood it (Marcus and the former intern) both left the organization. If its original credentials were ever weak or default, it may already function as a ready-made foothold for lateral movement, and nobody would currently know.

### Recommended Response: **Decommission**
Unlike the two data-storage cases above, this device's original purpose was never formalized, and its current state and integrity cannot be trusted simply because it might still be "useful." The appropriate first step is physical removal — locate the device, power it down, and preserve its storage for forensic review to determine what it was actually doing before disposal. Whether MedDefense subsequently builds proper, IT-owned network monitoring capability (addressing the real and already-documented detection gap from Task 5, Gap G-004) should be treated as a separate decision, made deliberately, rather than resurrecting an abandoned device of unknown provenance.

---

## Asset Registry Update

| Asset ID | Name | Type | Location | Owner (Dept) | OS/Platform | Critical Services | Network Segment | Status | Notes |
|---|---|---|---|---|---|---|---|---|---|
| A-040 | Dr. Patel's Personal NAS | Data Store | Central, Cardiology (Dr. Patel's office) | Unassigned (personal device) | Unknown (consumer NAS, model undocumented) | Cardiology research data storage | 10.10.1.0/24 (assumed) | **Shadow IT** | Connected directly to a hospital wall port; may contain patient-linked research data; recommended for migration to approved storage. |
| A-041 | Marketing Shared Google Drive | Data Store | Cloud (Google, personal account) | Unassigned (tied to individual's personal Gmail) | Google Drive (consumer) | Media files, press communications | N/A (cloud, outside org network) | **Shadow IT** | Linked to a personal Gmail identity; no organizational access control possible by design; recommended for migration to O365/SharePoint. |
| A-042 | Raspberry Pi (2nd Floor, Central) | Network Device | Central, 2nd floor | Unassigned (originally deployed by a former IT intern) | Unknown (Raspbian or similar; patch status unknown) | Unknown / originally intended as a network monitor | 10.10.1.0/24 (specific IP not identified) | **Shadow IT** | Abandoned since both the intern and Marcus departed; credentials and current function unverified; recommended for immediate decommission and forensic review. |

---

## Shadow IT Policy Recommendation

The single most effective policy change would be to pair a **fast, low-friction IT intake process** with a **standing, recurring network discovery requirement** — treating shadow IT as both a demand-side and a visibility problem, since fixing only one half leaves the other exposed. Dr. Patel and the marketing team didn't bypass IT out of malice; they did it because the official alternative was too slow or didn't exist, which means a genuinely responsive request process (with a committed turnaround time) removes the incentive to improvise in the first place. But that alone wouldn't have caught the Raspberry Pi, which nobody remembered to ask about — so it must be paired with mandatory, recurring network discovery scans (the same kind Sarah Park ran for Task 7) as standing quarterly practice rather than a one-time exercise, ensuring that anything plugged into the network eventually surfaces on its own, regardless of whether anyone thought to report it.
