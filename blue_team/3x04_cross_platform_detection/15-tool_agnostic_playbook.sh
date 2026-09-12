#!/bin/bash
# ==============================================================================
# Task 15 / 14: Tool-Agnostic Investigation Playbook Generation
# MedDefense Health Systems - SOC Tier 1 Analyst Module 3x04
# ==============================================================================

set -uo pipefail

PLAYBOOK_DIR="playbook"
mkdir -p "$PLAYBOOK_DIR"

start_time=$(date +%s)
PLAYBOOK_PATH="$PLAYBOOK_DIR/tool_agnostic_playbook.md"

cat << 'EOF' > "$PLAYBOOK_PATH"
# MedDefense Tool-Agnostic Investigation Playbook v1

## Purpose
This playbook defines a standardized, dual-interface investigation workflow for Tier 1 SOC analysts at MedDefense Health Systems. It ensures consistent threat triage across raw CLI environments and structured SIEM dashboards without platform lock-in.

## Scope
* **Covers:** Triage and validation of host-based credential theft, off-hours privileged access, and medical IoT egress anomalies.
* **Does Not Cover:** Incident containment execution, live host memory forensics, or malware reverse engineering.

## Inputs
Analysts must maintain access to the following locked operational assets:
* Enriched event pipeline logs (`enriched_events.json`)
* Asset inventory and classification records (`asset_inventory.json`)
* Behavioral baseline profiles (`baseline_spec.md`)
* Detection signature catalog (`detection_spec.md`)
* Threat intelligence IOC context (`ioc_context.json`)

## Workflow Steps

| Step | CLI Action (Pipeline/jq) | Dashboard Action (Export/UI) |
| :--- | :--- | :--- |
| **1. Scope Asset** | Query `asset_inventory.json` for host criticality and classification. | Open Dashboard, filter agent inventory by `agent.name`. |
| **2. Time Window** | Filter event arrays using ISO8601 start and end time boundaries. | Select absolute date-range picker matching incident window. |
| **3. Filter Events** | Execute `jq` filters for specific Sysmon/Windows event IDs. | Enter KQL query expression into Discover search bar. |
| **4. Extract Fields** | Isolate keys via projection (`.source.ip`, `.user.name`). | Expand document flyout to review `_source` attributes. |
| **5. Join Context** | Perform manual or script-based JSON joins with zone data. | Validate inline field population (`source.zone`). |
| **6. Check Trace** | Inspect raw log sequences and chronological intervals. | Replay saved dashboard trace steps and action paths. |
| **7. Evaluate TTPs** | Map observed behaviors to ATT&CK technique catalog. | Review dashboard summary markdown annotations. |
| **8. Emit Finding** | Write validated JSON object to `findings/`. | Export verified investigation package. |

## Field Name Translation Table

| Normalized Schema | Wazuh Field Name | Description |
| :--- | :--- | :--- |
| `src_ip` | `source.ip` | Originating IP address of network flow |
| `dst_ip` | `destination.ip` | Target IP address of network flow |
| `hostname` | `agent.name` | Monitored endpoint identifier |
| `user` | `user.name` | Authenticated user account |
| `event_id` | `winlog.event_id` | Windows Security / Sysmon event identifier |
| `raw_message` | `full_log` | Unparsed raw event payload string |
| `event_ref` | `_id` | Unique document reference identifier |
| `timestamp` | `@timestamp` | Primary event timestamp (UTC) |
| `data_class` | `agent.labels.data_classification` | Asset regulatory data classification |
| `zone_name` | `source.zone` | Network security segmentation zone |

## Query Decomposition Rule
Every investigation query must decompose into three atomic components:
1. **Filter Expression:** Criteria matching host, IP, or event ID.
2. **Aggregation / Grouping:** Sorting or counting matching records.
3. **Time Window:** Bounded start and end timestamps.
* *CLI (jq):* `[.[] | select(.host == "clin-ws-12" and .event_id == 10)] | length`
* *KQL:* `agent.name:"clin-ws-12" AND winlog.event_id:10`
* *Lucene:* `agent.name:clin-ws-12 AND winlog.event_id:10`

## Finding Schema
Every finding must conform to the locked JSON structure:
`finding_id`, `scenario_id`, `interface`, `investigation_start`, `investigation_end`, `time_to_first_answer_seconds`, `actions`, `fields_touched`, `event_refs`, `attack_techniques`, `hypothesis`, `confidence`, `created_at`.

## Exit Criteria
An investigation is complete when the hypothesis is validated, ATT&CK techniques are mapped, and a conforming finding JSON file is written to `findings/`.

## Known Pitfalls
1. Relying on unindexed agent labels without confirming inline asset metadata requires unexpected secondary lookups.
2. Omitting ISO8601 UTC timezone suffixes during CLI filtering leads to skewed time-window queries.
3. Failing to account for schema translation differences between flat files and Wazuh documents invalidates field projections.
EOF

end_time=$(date +%s)
elapsed=$((end_time - start_time))
[ $elapsed -lt 1 ] && elapsed=1

word_count=$(wc -w < "$PLAYBOOK_PATH")
printf "playbook    : %s written (%s words, %s seconds)\n" "$PLAYBOOK_PATH" "$word_count"
