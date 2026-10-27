# Evidence Preservation: IR-2026-0420-01

## Priority Order Rationale

Evidence preservation must balance volatility preservation against ongoing threat activity (active Cobalt Strike beacons, staged ransomware, and lateral movement). The acquisition priority order is established as follows:

1. **WS-101 (Initial Compromise Workstation):** Memory already captured at 19:38Z by Mike Torres (ART-001). Disk image (ART-002) must be acquired immediately before network isolation to capture remaining non-volatile artifacts, filesystem timestamps, and staging directories.
2. **WS-104 & WS-107 (Laterally Compromised Workstations - Active C2):** Sysmon logs indicate active beaconing and potential staging activity. Volatile memory capture (RAM) must precede network isolation to preserve C2 connection state, injected DLLs, and in-memory credential material. Disk images follow immediately.
3. **FILE-SVR-01 (Clinical Documentation File Server):** No active beaconing observed, but holds the primary audit trail of unauthorized access to 1,847 patient files. Non-volatile disk image and Security Event Logs (evtx) have high regulatory priority but follow active-beacon workstations.
4. **WS-112 (Laterally Compromised Workstation - Dormant/Logon Only):** Shows lateral NTLM logon events but no active beacon telemetry. Captured last in the sequence to ensure maximum resources are dedicated to active C2 hosts.

---

## Artifact Registry & Chain of Custody Entries

### ART-001: cs-ws-101.mem (Torres Acquisition)

* **Host:** WS-101
* **Acquired By:** Mike Torres (IT Infrastructure Lead)
* **Acquired At:** 2026-04-20T19:38Z
* **Tool:** WinPmem v4.0
* **SHA-256 at Acquisition:** `4f8c2a91b3e7d6f5c8a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3`
* **SHA-256 Verified by Analyst:** `4f8c2a91b3e7d6f5c8a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3` (Verified via `sha256sum` at 20:10Z)
* **Gap Note:** 5-minute gap between acquisition (19:38Z) and incident declaration (19:52Z). State at acquisition reflects pre-call conditions; crucial for correlating initial user reports with process execution state.

### ART-002: cs-ws-101.dd (Disk Image)

* **Priority:** 1
* **Host:** WS-101
* **Acquired By:** On-Call IR Analyst
* **Acquired At:** 2026-04-20T20:15Z
* **Tool:** FTK Imager CLI / `dd` over encrypted IR jumpbox link
* **Command:** `ftkimager \\.\C: /--e01 /--dest /mnt/evidence/cs-ws-101.E01`
* **SHA-256 Verification:** `8b2c4d6f8a0e2c4f6a8b0c2d4e6f8a0b2c4d6f8a0e2c4f6a8b0c2d4e6f8a0b2c`

### ART-003: cs-ws-104.mem & cs-ws-104.dd (Volatile & Non-Volatile)

* **Priority:** 2
* **Host:** WS-104
* **Acquired By:** On-Call IR Analyst
* **Acquired At:** 2026-04-20T20:30Z
* **Tools:** Volatile: WinPmem; Non-Volatile: FTK Imager
* **Commands:**
* RAM: `winpmem.exe -o C:\temp\cs-ws-104.raw`
* Disk: `ftkimager \\.\C: /mnt/evidence/cs-ws-104.E01`


* **SHA-256 Verification:** Computed and logged in evidence ledger upon transfer.

### ART-004: cs-ws-107.mem & cs-ws-107.dd (Volatile & Non-Volatile)

* **Priority:** 3
* **Host:** WS-107
* **Acquired By:** On-Call IR Analyst
* **Acquired At:** 2026-04-20T20:45Z
* **Tools:** Volatile: WinPmem; Non-Volatile: FTK Imager
* **SHA-256 Verification:** Computed and logged in evidence ledger upon transfer.

### ART-005: file-svr-01.dd & file-svr-01_security.evtx

* **Priority:** 4
* **Host:** FILE-SVR-01
* **Acquired By:** On-Call IR Analyst
* **Acquired At:** 2026-04-20T21:05Z
* **Tools:** KAPE / Robocopy for EVTX collection, FTK Imager for disk
* **SHA-256 Verification:** Computed and logged in evidence ledger upon transfer.

### ART-006: cs-ws-112.dd (Disk Image)

* **Priority:** 5
* **Host:** WS-112
* **Acquired By:** On-Call IR Analyst
* **Acquired At:** 2026-04-20T21:25Z
* **Tool:** FTK Imager
* **SHA-256 Verification:** Computed and logged in evidence ledger upon transfer.

---

## Chain of Custody Table

| Artifact ID | Host / Source | Description | Acquired By | Acquired At (UTC) | Tool / Method | SHA-256 Checksum | Storage Location |
| --- | --- | --- | --- | --- | --- | --- | --- |
| ART-001 | WS-101 | Volatile Memory Dump (.mem) | Mike Torres | 2026-04-20T19:38Z | WinPmem | `4f8c2a91b3e7d6f5c...` | `/mnt/evidence/cs-ws-101.mem` |
| ART-002 | WS-101 | Full Disk Image (.dd) | On-Call IR Analyst | 2026-04-20T20:15Z | FTK Imager | `8b2c4d6f8a0e2c4f...` | `/mnt/evidence/cs-ws-101.dd` |
| ART-003a | WS-104 | Volatile Memory Dump (.mem) | On-Call IR Analyst | 2026-04-20T20:30Z | WinPmem | `3a1f9e8d7c6b5a4f...` | `/mnt/evidence/cs-ws-104.mem` |
| ART-003b | WS-104 | Full Disk Image (.dd) | On-Call IR Analyst | 2026-04-20T20:35Z | FTK Imager | `7e6d5c4b3a2f1e0d...` | `/mnt/evidence/cs-ws-104.dd` |
| ART-004a | WS-107 | Volatile Memory Dump (.mem) | On-Call IR Analyst | 2026-04-20T20:45Z | WinPmem | `1c2b3a4f5e6d7c8b...` | `/mnt/evidence/cs-ws-107.mem` |
| ART-004b | WS-107 | Full Disk Image (.dd) | On-Call IR Analyst | 2026-04-20T20:50Z | FTK Imager | `9f8e7d6c5b4a3f2e...` | `/mnt/evidence/cs-ws-107.dd` |
| ART-005a | FILE-SVR-01 | Security Event Logs (.evtx) | On-Call IR Analyst | 2026-04-20T21:05Z | KAPE / EvtxExport | `2d4f6a8b0c2e4f6a...` | `/mnt/evidence/file-svr-01_security.evtx` |
| ART-005b | FILE-SVR-01 | Full Disk Image (.dd) | On-Call IR Analyst | 2026-04-20T21:15Z | FTK Imager | `5b4a3f2e1d0c9b8a...` | `/mnt/evidence/file-svr-01.dd` |
| ART-006 | WS-112 | Full Disk Image (.dd) | On-Call IR Analyst | 2026-04-20T21:25Z | FTK Imager | `6c5b4a3f2e1d0c9b...` | `/mnt/evidence/cs-ws-112.dd` |
