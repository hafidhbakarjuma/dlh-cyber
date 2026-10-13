# Incident Timeline: IR-2026-0414-01

## Header

| Field | Value |
|---|---|
| **incident_id** | IR-2026-0414-01 |
| **declared_at** | 2026-04-14T02:51:04Z |
| **declared_by** | On-Call SOC Analyst |
| **initial_severity** | SEV2 |
| **current_severity** | SEV2 |
| **ir_commander** | James Chen, SOC Lead |
| **scribe** | On-Call SOC Analyst |

---

## Legend

- **OBSERVATION** — raw fact from an alert, log, or artifact
- **DECISION** — a choice made by an authorized actor, with rationale
- **ACTION** — an operation executed against an asset, with owner
- **COMMUNICATION** — a message sent or received, with audience
- **EVIDENCE** — a preserved artifact with hash and storage path

---

## Entries

### 2026-04-14T02:47:11Z | OBSERVATION

**SIEM rule wz-edr-100041** — `powershell.exe` parent of `msbuild.exe` on `WST-WS-031` with outbound connection to `185.220.101.47:443`

- **source:** alert `A-20260414-9841.json`
- **certainty:** confirmed

---

### 2026-04-14T02:47:15Z | OBSERVATION

**Proxy Log** — Web proxy recorded outbound HTTPS traffic from `WST-WS-031` to known external malicious C2 IP `185.220.101.47` under account `dmarsh`

- **source:** `proxy_24h_dmarsh.log`
- **certainty:** high

---

### 2026-04-14T02:49:30Z | COMMUNICATION

**James Chen** — Channel message received: *"You own this. Contain it. Document everything."*

- **source:** Slack/Teams `#incidents`
- **certainty:** confirmed

---

### 2026-04-14T02:51:04Z | DECISION

**On-Call SOC Analyst** — Incident declared at **SEV2**: confirmed C2 beaconing from clinical workstation `WST-WS-031`; clinical/LIS access confirmed, data exposure/exfiltration not yet confirmed

- **source:** alert `A-20260414-9841.json` + `proxy_24h_dmarsh.log`
- **certainty:** confirmed
