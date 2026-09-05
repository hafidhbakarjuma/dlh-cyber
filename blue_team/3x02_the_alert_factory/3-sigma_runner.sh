#!/bin/bash
set -euo pipefail

# Parse arguments
RULE_FILE=""
EVIDENCE_FILE=""
DRY_RUN=false
COUNT_ONLY=false
WINDOW=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        --count-only)
            COUNT_ONLY=true
            shift
            ;;
        --window)
            WINDOW="$2"
            shift 2
            ;;
        *)
            if [[ -z "$RULE_FILE" ]]; then
                RULE_FILE="$1"
            elif [[ -z "$EVIDENCE_FILE" ]]; then
                EVIDENCE_FILE="$1"
            fi
            shift
            ;;
    esac
done

if [[ -z "$RULE_FILE" ]]; then
    echo "Usage: $0 <rule_file> [evidence_file] [--dry-run] [--count-only] [--window start,end]" >&2
    exit 1
fi

HANDOFF_DIR="${HANDOFF_DIR:-$HOME/3x00_handoff/evidence_handoff}"
if [[ -z "$EVIDENCE_FILE" ]]; then
    if [[ -r "$HANDOFF_DIR/data/normalized_events.json" ]]; then
        EVIDENCE_FILE="$HANDOFF_DIR/data/normalized_events.json"
    elif [[ -r "/home/student/3x00_evidence_pipeline/normalized_events.json" ]]; then
        EVIDENCE_FILE="/home/student/3x00_evidence_pipeline/normalized_events.json"
    elif [[ -r "/home/student/3x00_evidence_pipeline/enriched_events.json" ]]; then
        EVIDENCE_FILE="/home/student/3x00_evidence_pipeline/enriched_events.json"
    else
        EVIDENCE_FILE="$HANDOFF_DIR/data/normalized_events.json"
    fi
fi

python3 - "$RULE_FILE" "$EVIDENCE_FILE" "$DRY_RUN" "$COUNT_ONLY" "$WINDOW" << 'PY'
import sys
import os
import json
import yaml
import time
from datetime import datetime
from collections import defaultdict

rule_path = sys.argv[1]
evidence_path = sys.argv[2]
dry_run = sys.argv[3].lower() == 'true'
count_only = sys.argv[4].lower() == 'true'
window_arg = sys.argv[5]

start_time = time.time()

# 1. Validate Rule YAML
try:
    with open(rule_path, 'r', encoding='utf-8') as f:
        rule = yaml.safe_load(f)
except Exception as e:
    if dry_run:
        print(f"ERROR: {e}")
        sys.exit(1)
    raise

required_fields = ['title', 'id', 'status', 'logsource', 'detection']
for rf in required_fields:
    if rf not in rule:
        msg = f"Missing required field: {rf}"
        if dry_run:
            print(msg)
            sys.exit(1)
        else:
            raise ValueError(msg)

# Check condition at top-level or inside detection block
detection = rule.get('detection', {})
condition = rule.get('condition') or detection.get('condition', '')
if not condition:
    msg = "Missing required field: condition"
    if dry_run:
        print(msg)
        sys.exit(1)
    else:
        raise ValueError(msg)

if dry_run:
    print("VALID")
    sys.exit(0)

# 2. Load Evidence
events = []
if os.path.exists(evidence_path):
    with open(evidence_path, 'r', encoding='utf-8') as f:
        first_char = f.read(1)
        f.seek(0)
        if first_char == '[':
            try:
                events = json.load(f)
            except Exception:
                pass
        if not events:
            for line in f:
                line_s = line.strip()
                if line_s:
                    try:
                        events.append(json.loads(line_s))
                    except Exception:
                        pass

window_start, window_end = None, None
if window_arg:
    parts = window_arg.split(',')
    if len(parts) == 2:
        window_start, window_end = parts[0].strip(), parts[1].strip()

selection = detection.get('selection', {})
timeframe_str = detection.get('timeframe', '')

for ev in events:
    ts = ev.get('timestamp', ev.get('@timestamp', ev.get('time', '')))
    if ts and 'hour_of_day' not in ev:
        try:
            dt = datetime.fromisoformat(ts.replace('Z', '+00:00'))
            ev['hour_of_day'] = dt.hour
        except Exception:
            pass

filtered_events = []
for ev in events:
    ts = ev.get('timestamp', ev.get('@timestamp', ''))
    if window_start and window_end and ts:
        if not (window_start <= ts <= window_end):
            continue
    filtered_events.append(ev)

def matches_selection(ev, sel):
    for k, v in sel.items():
        ev_val = ev.get(k)
        if isinstance(v, list):
            if ev_val not in v and str(ev_val) not in [str(x) for x in v]:
                return False
        else:
            if ev_val != v and str(ev_val) != str(v):
                return False
    return True

matched_events = []
is_aggregation = 'count(' in condition and 'by' in condition

if is_aggregation:
    threshold = 5
    if '>' in condition:
        try:
            threshold = int(condition.split('>')[-1].strip())
        except Exception:
            pass

    tf_seconds = 120
    if timeframe_str.endswith('s'):
        try:
            tf_seconds = int(timeframe_str[:-1])
        except Exception:
            pass

    sel_events = [ev for ev in filtered_events if matches_selection(ev, selection)]
    
    def get_ts(e):
        return e.get('timestamp', e.get('@timestamp', ''))
    
    sel_events_sorted = sorted([e for e in sel_events if get_ts(e)], key=get_ts)
    ip_groups = defaultdict(list)
    for ev in sel_events_sorted:
        src = ev.get('src_ip', 'unknown')
        ip_groups[src].append(ev)

    for src, evs in ip_groups.items():
        if len(evs) >= threshold:
            for i in range(len(evs)):
                window_sub = [evs[i]]
                t_i = datetime.fromisoformat(get_ts(evs[i]).replace('Z', '+00:00'))
                for j in range(i + 1, len(evs)):
                    t_j = datetime.fromisoformat(get_ts(evs[j]).replace('Z', '+00:00'))
                    if (t_j - t_i).total_seconds() <= tf_seconds:
                        window_sub.append(evs[j])
                if len(window_sub) >= threshold:
                    matched_events.extend(window_sub)
                    break
    
    unique_matches = {}
    for ev in matched_events:
        key = (ev.get('timestamp'), ev.get('hostname'), ev.get('src_ip'), ev.get('user'))
        unique_matches[key] = ev
    matched_events = list(unique_matches.values())

else:
    for ev in filtered_events:
        if matches_selection(ev, selection):
            matched_events.append(ev)

execution_time = int((time.time() - start_time) * 1000)

match_references = []
for ev in matched_events:
    match_references.append({
        "timestamp": ev.get('timestamp', ev.get('@timestamp', '')),
        "hostname": ev.get('hostname', ev.get('host', 'unknown')),
        "event_ref": ev.get('event_id', ev.get('id', 'event'))
    })

if count_only:
    print(len(match_references))
    sys.exit(0)

output = {
    "rule_id": rule.get('id'),
    "rule_title": rule.get('title'),
    "level": rule.get('level'),
    "evidence_path": evidence_path,
    "match_count": len(match_references),
    "matches": match_references,
    "execution_time_ms": execution_time
}

print(json.dumps(output, indent=2))
PY
