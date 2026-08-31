#!/bin/bash
set -euo pipefail

# Default HANDOFF_DIR if unset, following project specifications
HANDOFF_DIR="${HANDOFF_DIR:-$HOME/3x00_handoff/evidence_handoff}"
DATA_FILE="$HANDOFF_DIR/data/enriched_events.json"

# Validate that the data file exists
if [ ! -f "$DATA_FILE" ]; then
    echo "Error: Enriched dataset not found at $DATA_FILE" >&2
    exit 1
fi

TAXONOMY_JSON="event_taxonomy.json"
LABELED_NDJSON="labeled_events.json"

# 1. Generate event_taxonomy.json definitions
cat << 'EOF' > "$TAXONOMY_JSON"
[
  {"canonical_label": "login_success", "source_type": "auth", "match": {"action": "success"}},
  {"canonical_label": "login_success", "source_type": "auth", "match": {"status": "success"}},
  {"canonical_label": "login_failure", "source_type": "auth", "match": {"action": "failure"}},
  {"canonical_label": "login_failure", "source_type": "auth", "match": {"status": "failure"}},
  {"canonical_label": "logout", "source_type": "auth", "match": {"action": "logout"}},
  {"canonical_label": "account_lockout", "source_type": "auth", "match": {"action": "lockout"}},
  {"canonical_label": "privilege_escalation", "source_type": "auth", "match": {"action": "privilege_escalation"}},
  {"canonical_label": "privilege_escalation", "source_type": "auditd", "match": {"syscall": "setuid"}},
  {"canonical_label": "process_start", "source_type": "auditd", "match": {"type": "EXECVE"}},
  {"canonical_label": "process_start", "source_type": "sysmon", "match": {"event_id": "1"}},
  {"canonical_label": "process_stop", "source_type": "auditd", "match": {"type": "PROCTITLE"}},
  {"canonical_label": "process_stop", "source_type": "sysmon", "match": {"event_id": "5"}},
  {"canonical_label": "child_process_spawn", "source_type": "sysmon", "match": {"event_id": "1"}},
  {"canonical_label": "file_read_sensitive", "source_type": "auditd", "match": {"syscall": "open", "mode": "read"}},
  {"canonical_label": "file_write_sensitive", "source_type": "auditd", "match": {"syscall": "open", "mode": "write"}},
  {"canonical_label": "file_permission_change", "source_type": "auditd", "match": {"syscall": "chmod"}},
  {"canonical_label": "file_permission_change", "source_type": "auditd", "match": {"syscall": "chown"}},
  {"canonical_label": "network_connection_outbound", "source_type": "suricata", "match": {"action": "allowed", "direction": "outbound"}},
  {"canonical_label": "network_connection_outbound", "source_type": "zeek", "match": {"conn_state": "SF"}},
  {"canonical_label": "network_connection_inbound", "source_type": "suricata", "match": {"action": "allowed", "direction": "inbound"}},
  {"canonical_label": "network_alert", "source_type": "suricata", "match": {"event_type": "alert"}},
  {"canonical_label": "network_blocked", "source_type": "suricata", "match": {"action": "blocked"}}
]
EOF

# 2. Process dataset (handling NDJSON), apply taxonomy rules, and generate labeled_events.json
python3 - << 'PY_SCRIPT'
import json
import sys
import os

data_file = os.path.expandvars("$HANDOFF_DIR/data/enriched_events.json")
taxonomy_file = "event_taxonomy.json"
output_file = "labeled_events.json"

with open(taxonomy_file, "r") as f:
    taxonomy = json.load(f)

events = []
with open(data_file, "r") as f:
    for line in f:
        line = line.strip()
        if line:
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue

labeled_count = 0
unlabeled_count = 0
label_distribution = {}

def match_rule(event, rule):
    src_fields = ['source', 'source_type', 'log_source']
    event_src = None
    for sf in src_fields:
        if sf in event and event[sf]:
            event_src = str(event[sf]).lower()
            break
    
    rule_src = rule.get("source_type", "").lower()
    if rule_src and event_src and rule_src != event_src:
        return False
        
    match_conds = rule.get("match", {})
    for k, v in match_conds.items():
        val = str(event.get(k, "")).lower()
        if val != str(v).lower():
            return False
            
    return True

out_lines = []
for event in events:
    assigned_label = "unlabeled"
    for rule in taxonomy:
        if match_rule(event, rule):
            assigned_label = rule["canonical_label"]
            break
            
    event["canonical_label"] = assigned_label
    if assigned_label != "unlabeled":
        labeled_count += 1
    else:
        unlabeled_count += 1
        
    label_distribution[assigned_label] = label_distribution.get(assigned_label, 0) + 1
    out_lines.append(json.dumps(event))

with open(output_file, "w") as out_f:
    out_f.write("\n".join(out_lines) + "\n")

print(f"taxonomy rules         : {len(taxonomy)}")
print(f"records labeled        : {labeled_count}")
print(f"records unlabeled      : {unlabeled_count}")
print("canonical label distribution (top 10):")

sorted_labels = sorted(label_distribution.items(), key=lambda x: x[1], reverse=True)
for label, count in sorted_labels[:10]:
    print(f"  {label:<26} {count}")

print("event_taxonomy.json written")
print("labeled_events.json written")
PY_SCRIPT
