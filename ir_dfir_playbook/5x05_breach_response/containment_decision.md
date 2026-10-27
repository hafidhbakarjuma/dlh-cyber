# Containment Decision: IR-2026-0420-01

## 1. Options Analysis

### Option A: Full Network Isolation (Enterprise-Wide Air Gap)
- **Action:** Sever all external WAN/Internet connections and isolate all internal subnet VLANs across MedDefense Site A simultaneously.
- **Effect on Attacker:** Immediately severs active C2 beaconing and halts any potential remote-triggered ransomware detonation or lateral movement.
- **Effect on Patient Care:** Catastrophic. Halts electronic health record (EHR) access, real-time telemetry, pharmacy dispensaries, and clinical communications across the entire site.
- **Evidence Preserved / Destroyed:** Preserves all volatile RAM and disk states across all endpoints. Destroys transient runtime network state counters on core switches.
- **Time to Execute:** 2 minutes.
- **Reversibility:** Fully reversible via administrative command, though operational restoration requires phased validation.

### Option B: Targeted Host Isolation & Precision Egress Block (Selected Strategy)
- **Action:** Isolate the four affected workstations (`WS-101`, `WS-104`, `WS-107`, `WS-112`) via EDR network containment, restrict `FILE-SVR-01` access to essential clinical services only, blackhole the C2 infrastructure IP/domain at the perimeter firewall, and preserve local runtime states.
- **Effect on Attacker:** Cuts off C2 communication channels, blocks further lateral movement paths originating from compromised hosts, and traps staging scripts without triggering alarms that precipitate automated ransomware execution.
- **Effect on Patient Care:** Minimal to negligible. Site A clinical operations continue uninterrupted on unaffected workstations; file server access remains restricted to authenticated clinical applications.
- **Evidence Preserved / Destroyed:** Preserves volatile memory and disk forensic integrity across all five hosts before isolation takes effect. Zero forensic evidence destroyed.
- **Time to Execute:** 8 minutes.
- **Reversibility:** Highly reversible via EDR command console and firewall rule rollback.

### Option C: Monitor and Trace (In-Place Surveillance)
- **Action:** Maintain live network connectivity while logging all attacker actions, C2 traffic, and lateral movement in real-time without taking hosts offline.
- **Effect on Attacker:** Allows observation of attacker intent and potential identification of broader infrastructure.
- **Effect on Patient Care:** Unaffected in the short term, but carries unacceptably high risk of catastrophic ransomware detonation given that staging scripts are already present on four workstations.
- **Evidence Preserved / Destroyed:** Maximizes real-time behavioral logging at the cost of extreme operational and patient safety risk.
- **Time to Execute:** Instantaneous.
- **Reversibility:** Irreversible if ransomware executes during observation.

---

## 2. Chosen Strategy & Trade-Off Rationale

**Option B (Targeted Host Isolation & Precision Egress Block)** is selected. Given that active Cobalt Strike beacons have operated for 72 hours and ransomware staging scripts are already present on system directories, passive monitoring (Option C) presents an existential threat to patient safety and data integrity. Conversely, enterprise-wide air-gapping (Option A) would paralyze critical clinical care at Site A. Option B strikes the necessary operational balance: it neutralizes the active C2 vector and locks down laterally compromised endpoints while leaving uncompromised clinical workstations and vital infrastructure online. This protects 1,847 patient records from exfiltration while upholding our ethical and legal duty of continuous patient care.

- **Authorizing Role:** Chief Information Security Officer (CISO) in coordination with the Chief Medical Officer (CMO).
- **Rollback Trigger:** If targeted EDR isolation inadvertently severs vital clinical life-support or emergency record systems required for immediate patient survival, isolate only the specific network interface while keeping local clinical applications running under strict supervision.
