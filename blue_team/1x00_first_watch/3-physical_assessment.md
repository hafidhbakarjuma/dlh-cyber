# MedDefense Health Systems
## The Walk-Through — Structured Risk Decomposition

**Prepared by:** Junior Security Analyst
**Prepared for:** James Chen, Deputy CISO
**Context:** On-site physical walk-through of MedDefense Central

---

### Observation 1: Server Room Access

- **Vulnerability:** The server room uses the same generic badge issued to every employee regardless of role (clinical, administrative, custodial), has no camera on the door, and keeps no visitor log.
- **Threat:** Any badge holder, or anyone who tailgates through the shared cafeteria corridor behind a legitimate badge holder, can enter the room housing every core server (EHR, billing, domain controllers, PACS, backups) with zero identity verification and zero record of the entry.
- **Impact:** Confidentiality (direct physical access enables data theft or device tampering to read data at rest), Integrity (physical access allows unauthorized modification of servers, e.g. planting hardware/software), Availability (theft, sabotage, or accidental damage could take core systems offline). All three pillars are exposed simultaneously.
- **Severity:** **Critical** — this single point of physical entry protects nearly every critical server identified in the asset inventory, and there is no detective control (camera, log) to even know a breach occurred.

---

### Observation 2: Network Closet

- **Vulnerability:** The second-floor network closet has no functioning lock, sits ajar, and displays switch management credentials in plaintext on a laminated sheet inside.
- **Threat:** Any passerby — staff, contractor, visitor who wandered off a public corridor — can open the closet, read the credentials, and log into the switch management interface directly, or physically connect a rogue device to an open port.
- **Impact:** Given the network is flat with no VLAN segmentation (per Task 0 findings), compromising this switch stack threatens Confidentiality (traffic interception/port mirroring), Integrity (reconfiguring switches, redirecting traffic), and Availability (disabling ports, causing outages) across the entire 10.10.0.0/16 network, not just this floor.
- **Severity:** **Critical** — trivial physical access plus posted credentials gives immediate control over core network infrastructure with organization-wide blast radius.

---

### Observation 3: Nurse Station

- **Vulnerability:** The EHR workstation has no enforced session timeout, is unattended with a patient record on screen, and hospital signage actively instructs staff not to log out between shifts.
- **Threat:** Any passerby in a public-adjacent clinical area — another patient, a visitor, an unauthorized staff member — can view the exposed PHI or interact with the session under someone else's authenticated identity.
- **Impact:** Confidentiality (PHI visible to anyone walking past), Integrity (any action taken during this window is attributable to the logged-in clinician, not the actual actor — an accountability failure as much as a technical one).
- **Severity:** **High** — this is a systemic, sanctioned practice (formalized by the sign) rather than an isolated lapse, meaning the exposure is continuous and hospital-wide rather than a one-off incident.

---

### Observation 4: Medical IoT (Vital Signs Monitor)

- **Vulnerability:** The device runs firmware last updated in 2019 (effectively unpatched for years) and sits on the same flat network segment as general clinical workstations, with no isolation between medical devices and the rest of the network.
- **Threat:** An attacker who gains a foothold anywhere on that shared segment (e.g., via the nurse station, or laterally from a compromised workstation) can reach and exploit known vulnerabilities in outdated device firmware to manipulate its behavior or readings.
- **Impact:** Integrity (falsified vital sign readings could directly drive incorrect clinical decisions — a patient safety consequence, not just a data one), Availability (the device could be disabled or rendered unreliable). This is one of the few observations where the CIA impact translates into direct physical patient harm.
- **Severity:** **Critical** — the combination of unpatched firmware, zero network segmentation, and direct patient-safety consequences makes this one of the most severe findings of the walk-through, independent of likelihood.

---

### Observation 5: Emergency Exit

- **Vulnerability:** A fire exit connecting the public waiting area directly to the restricted administrative wing (including the IT department) is permanently propped open, defeating its access control entirely, with staff sanctioning the practice via a handwritten sign.
- **Threat:** Any member of the public in the waiting area can walk unimpeded into the restricted wing without any credential, badge, or challenge, gaining proximity to IT systems and staff.
- **Impact:** Primarily Confidentiality and Integrity exposure once inside the restricted wing (proximity to IT equipment, unattended terminals, physical documents), with a secondary physical-security dimension (unauthorized presence near executive/IT staff).
- **Severity:** **High** — severe because it bypasses access control entirely and leads toward IT space, but rated below the server room/network closet findings since it is one step removed from direct equipment access rather than a direct hit.

---

*Pattern: every Critical finding requires no skill or tooling — just physical presence — and its blast radius reaches far beyond the single item observed. Severity here tracks ease-of-exploitation × downstream reach, not worst-case optics alone.*
