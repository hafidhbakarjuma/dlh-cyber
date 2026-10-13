# Containment Strategy and Trade-offs: IR-2026-0414-01

## Executive Summary

This document outlines the evaluation of containment options for clinical workstation **WST-WS-031**, where malicious process activity (`msbuild.exe` spawned by `powershell.exe`) and confirmed command-and-control beaconing under user account `dmarsh` were detected at **02:47:11Z**. In a clinical environment, containment decisions must balance the imperative to stop active data exfiltration or lateral movement against the operational impact on patient care and the Laboratory Information System (LIS).

---

## Asset Context & Operational Dependencies

| Field | Value |
|---|---|
| **Asset** | WST-WS-031 (West Campus Clinical Workstation) |
| **Primary Function** | Accessing and interacting with the Laboratory Information System (LIS) and clinical data services. |
| **User Account** | `dmarsh` (Daniel Marsh, Laboratory Technician) |

**Operational Risk:** Disrupting an active clinical workstation during critical hours can delay lab sample processing, blood work validations, and patient diagnostics. However, leaving a compromised endpoint uncontained risks lateral movement into the core LIS API and broader enterprise network.

---

## Evaluation of Containment Options

### Option 1: Full Network Isolation (EDR Host Isolation)

**Description:** Remotely isolate WST-WS-031 from the network via EDR agent command, cutting off all network communication except management console traffic.

**Pros:**

- Immediately severs C2 communication (terminating connection to `185.220.101.47:443`).
- Prevents potential lateral movement or credential dumping tools from reaching other internal subnets.

**Cons:**

- Immediately blocks the user (`dmarsh`) or any automated LIS background service from communicating with the LIS API from this node.
- May disrupt ongoing sample intake or clinical data entry if the workstation was actively in use.

**Operational Cost:** Moderate-High (Clinical impact on West Campus laboratory throughput).

---

### Option 2: Process Termination & Account Suspension Only (No Network Isolate)

**Description:** Kill the malicious process tree (`powershell.exe` → `msbuild.exe`) and disable user account `dmarsh` in Active Directory / Azure AD, leaving the workstation connected to the network.

**Pros:**

- Preserves workstation network connectivity for remote forensic triage or live capture.
- Stops the active execution chain and locks out the compromised user identity.

**Cons:**

- High risk of persistence re-triggering (scheduled tasks, services, or registry run keys spawning new processes).
- Leaves the host vulnerable if secondary persistence mechanisms or secondary threat actor access channels (e.g., alternative local/service accounts) exist.

**Operational Cost:** Low for network operations, but dangerously high risk of re-infection.

---

### Option 3: Targeted Firewall Rule / Port Blocking (Micro-containment)

**Description:** Block outbound traffic specifically to destination IP `185.220.101.47` while keeping general network access open.

**Pros:**

- Keeps the workstation online for clinical duties while cutting off the known C2 server.

**Cons:**

- Attackers can easily pivot to secondary C2 channels, alternative ports, or domain fronts.
- Inadequate for handling an active compromise on a high-value clinical endpoint.

**Operational Cost:** Low impact, but unacceptable security risk.

---

## Selected Containment Strategy & Justification

**Chosen Action:** Option 1 (Full Network Isolation via EDR) combined with User Account Lockout (`dmarsh`).

**Rationale:**

- The presence of script-based execution (`powershell.exe` launching `msbuild.exe`) communicating with an external malicious IP on a clinical workstation presents an unacceptable risk to patient data confidentiality and integrity.
- While clinical impact is a concern, the potential for lateral movement into the LIS core infrastructure outweighs localized workstation disruption.
- Evidence preservation must strictly precede or occur concurrently via EDR live response before isolation takes effect.

---

## Execution Plan & Verification

1. **Verify Evidence Capture:** Ensure volatile memory and EDR telemetry buffers have been successfully dumped and hashed (`/evidence/IR-2026-0414-01/`).
2. **Execute Isolation:** Issue EDR isolation command for WST-WS-031.
3. **Revoke Credentials:** Disable user account `dmarsh` across Active Directory and Azure AD.
4. **Verify Containment:** Confirm isolation status via EDR control plane (ping/connection test failure from host) and log the action in `incident_timeline.md`.
