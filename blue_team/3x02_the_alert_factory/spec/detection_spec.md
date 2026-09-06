# MedDefense Detection Engineering Specification

## Purpose
This specification defines the vendor-neutral detection engineering lifecycle, governance standards, and operational interfaces for MedDefense Health Systems. It serves as the definitive engineering contract for maintaining HIPAA-compliant visibility across our hybrid Linux and Windows infrastructure.

## Inputs
*   **Normalized Dataset**: `$NORM_DIR/normalized_events.json` (Resolved via environment variable `NORM_DIR`).
*   **Baseline Summary**: `$BASELINE_PKG/baselines/baseline_summary.json` (Resolved via `BASELINE_PKG`).
*   **Risk Register**: `$ASSETS_DIR/risk_register.json` (Resolved via `ASSETS_DIR`).
*   **Asset Inventory**: `$HANDOFF_DIR/context/asset_inventory.json` (Resolved via `HANDOFF_DIR`).

## Rule Authoring Standard
All detection rules must be authored in valid Sigma YAML format. Required top-level fields include `id`, `title`, `description`, `level`, `status`, `author`, `references`, `logsource`, `detection`, and `tags`. Rules must adhere to snake_case naming conventions (`NNN_descriptive_name.yml`) and include at least one official MITRE ATT&CK tag (`attack.tXXXX`).

## Execution Model
Rules are evaluated via the custom `3-sigma_runner.sh` engine, which translates Sigma syntax into query filters executed against normalized JSON event streams. Evaluations support precise ISO 8601 windowing (`--window START,END`) and aggregation primitives (`--count-only`) to isolate baseline behaviors from malicious activity.

## Quality Thresholds
Rules must meet strict performance gates before entering production:
*   **STRONG**: $F1 \ge 0.70$ (High confidence, balanced precision and recall).
*   **WEAK**: $F1 < 0.30$ (Requires immediate tuning or deprecation).
*   **False Positive Rate**: Baseline FP generation must not exceed 10 events per 7-day window without documented environment exceptions.

## Tuning Protocol
Noisy rules producing excessive false positives are routed to `rules/sigma/tuned/`. Tuning requires refining Sigma selection blocks or adding explicit filters for known maintenance hosts/processes. Changes must be validated using `10-fp_baseline.sh` and re-scored using `13-rule_quality.sh`.

## Risk Ranking Model
Catalog priority is calculated via risk-based weighting:
$$\text{Priority Score} = \sum (\text{Likelihood} \times \text{Impact}) \times F1$$
Rules with an $F1$ score of zero are assigned a safety floor of $\text{Risk Score} \times 0.1$. Unmatched rules are classified as `ORPHAN`.

## Outputs
The pipeline generates `alert_queue.json`, containing deduplicated, risk-scored alerts adhering to `alert_queue_schema.json`. This serves as the immutable data contract consumed directly by the 3x03 Tier 1 triage shift.

## Failure Modes
1. **Schema Drift**: Downstream 3x03 consumers break if event summary keys change. *Symptom*: Triage parser exceptions.
2. **Log Ingestion Stalling**: Missing telemetry causes false negatives in correlation rules. *Symptom*: Unexplainable drop in raw matches.
3. **Clock Skew**: Desynchronized timestamps corrupt 60-second deduplication windows. *Symptom*: Duplicate alert spam.

## Reviewer Checklist
* [ ] Valid YAML syntax and unique rule ID.
* [ ] At least one valid MITRE ATT&CK technique tag.
* [ ] $F1 \ge 0.70$ verified against ground truth.
* [ ] Asset context and priority score correctly assigned.
* [ ] Deduplication and schema compliance validated.
