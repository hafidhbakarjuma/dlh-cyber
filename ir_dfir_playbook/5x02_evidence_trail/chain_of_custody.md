# Chain of Custody: LH-2026-0414-01

## Case Header

| Field | Value |
|---|---|
| Case number | LH-2026-0414-01 |
| Incident ID | IR-2026-0414-01 |
| Lead investigator | IR Analyst |
| Date opened | 2026-04-14 |
| Litigation hold reference | Memo from Helena Reyes, 2026-04-14T07:30Z |

## Artifact Registry

| Artifact ID | Name | Format | Acquired By | Acquired At (UTC) | Tool | SHA-256 at Acquisition | Storage Path | Access Controls |
|---|---|---|---|---|---|---|---|---|
| ART-001 | wst-ws-031.dd | RAW | J. Vance (IR Team) | 2026-04-14T08:15Z | FTK Imager CLI | e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 | /evidence/5x02/wst-ws-031.dd | read-only, IR team only |
| ART-002 | wst-ws-031.mem | RAW | J. Vance (IR Team) | 2026-04-14T08:45Z | WinPmem | 5df417c254b7c6f2a89091392657e5e347b7f1414446b0d91244e83c748259f9 | /evidence/5x02/wst-ws-031.mem | read-only, IR team only |
| ART-003 | wst-ws-017.mem | RAW | J. Vance (IR Team) | 2026-04-14T09:20Z | WinPmem | 9b71d227690a209b552382894562548811e5927515c1e5522718928372619102 | /evidence/5x02/wst-ws-017.mem | read-only, IR team only |

## Access Log

| Timestamp (UTC) | Actor | Artifact ID | Action | Tool | Hash Verified | Notes |
|---|---|---|---|---|---|---|
| 2026-04-14T10:00Z | IR Analyst | ART-001 | hash_verify | sha256sum | yes | Baseline established; SHA-256 matches acquisition record. |
| 2026-04-14T10:05Z | IR Analyst | ART-002 | hash_verify | sha256sum | yes | Baseline established; SHA-256 matches acquisition record. |
| 2026-04-14T10:10Z | IR Analyst | ART-003 | hash_verify | sha256sum | yes | Baseline established; SHA-256 matches acquisition record. |