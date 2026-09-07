# MedDefense SOC Triage Methodology

## Classification Taxonomy
* **true_positive**: Malicious or unauthorized activity identified by a rule where adversary intent is confirmed by event telemetry (e.g., Rule 010 credential theft hitting unauthorized process memory).
* **false_positive**: Authorized operational activity incorrectly flagged by a rule due to overly broad logic or missing baseline context (e.g., Rule 001 SSH brute force triggered by automated backup monitoring).
* **benign**: Legitimate administrative activity that matches detection signatures but presents zero security risk (e.g., Rule 004 recon tool execution run during routine system diagnostics).
* **escalated**: A confirmed true positive requiring Tier 2 incident response, forensic deep-dive, containment, and cross-functional reporting (e.g., Rule 012 medical segment egress exfiltrating patient records).

## Priority Ordering Rule
Analysts work the queue strictly descending by `priority_score` from `alert_queue.json`. Override condition: Alerts hitting hosts marked as critical in `asset_inventory.json` (such as `db-patient-01`) are prioritized above lower-scored alerts regardless of queue position.

## Evidence Requirement
Every classification must reference concrete fields from `enriched_events.json`—specifically `src_ip`, `dest_ip`, `username`, `process_name`, or `timestamp`. Purely subjective closures without named field values are prohibited.

## Escalation Criteria
Escalation to Tier 2 is triggered if and only if the following boolean predicate evaluates to true:
* `classification == true_positive` AND (`target_host` in critical inventory OR `ioc_reputation == "malicious"`).

## SLA
* **Critical** ($\ge 20$): 15 minutes
* **High** (10–19): 30 minutes
* **Medium** (5–9): 60 minutes
* **Low** (1–4): Same shift completion

## Documentation Standard
Every processed alert must produce a structured ticket containing these mandatory fields:
* [ ] `ticket_id` (deterministic from alert_id)
* [ ] `alert_id` (source queue reference)
* [ ] `classification` (true_positive, false_positive, benign, escalated)
* [ ] `justification` (field-backed narrative)
* [ ] `evidence_refs` (pointers into `enriched_events.json`)
* [ ] `ioc_hits` (`ioc_context.json` entries)
* [ ] `attack_techniques` (ATT&CK technique IDs)
* [ ] `recommended_action` (close, escalate_tier2, monitor, tune_rule)
* [ ] `analyst_time_seconds` (processing duration)
* [ ] `created_at` (ISO 8601 UTC timestamp)
