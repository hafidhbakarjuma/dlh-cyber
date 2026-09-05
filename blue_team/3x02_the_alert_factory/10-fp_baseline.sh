#!/bin/bash
set -euo pipefail

RULES_DIR="rules/sigma"
OUTPUT_JSON="fp_baseline.json"
BASELINE_SUMMARY="${BASELINE_PKG:-$HOME/3x00_handoff/evidence_handoff}/baselines/baseline_summary.json"

# Default baseline window if summary file is not found
START_ISO="2026-03-18T00:00:00Z"
END_ISO="2026-03-24T23:59:59Z"

if [[ -f "$BASELINE_SUMMARY" ]]; then
    parsed_start=$(python3 -c "import json; print(json.load(open('$BASELINE_SUMMARY')).get('start_time', '$START_ISO'))" 2>/dev/null || echo "$START_ISO")
    parsed_end=$(python3 -c "import json; print(json.load(open('$BASELINE_SUMMARY')).get('end_time', '$END_ISO'))" 2>/dev/null || echo "$END_ISO")
    if [[ -n "$parsed_start" ]]; then START_ISO="$parsed_start"; fi
    if [[ -n "$parsed_end" ]]; then END_ISO="$parsed_end"; fi
fi

# Extract YYYY-MM-DD for display (fixed cut option)
WINDOW_START_DISP=$(echo "$START_ISO" | cut -d'T' -f1)
WINDOW_END_DISP=$(echo "$END_ISO" | cut -d'T' -f1)

# Count rules
rule_files=("$RULES_DIR"/*.yml "$RULES_DIR"/*.yaml)
valid_rules=()
for rf in "${rule_files[@]}"; do
    if [[ -f "$rf" ]]; then
        valid_rules+=("$rf")
    fi
done

rule_count=${#valid_rules[@]}
echo "evaluating $rule_count rules against baseline window $WINDOW_START_DISP -> $WINDOW_END_DISP"

python3 - "${valid_rules[*]}" "$START_ISO" "$END_ISO" "$OUTPUT_JSON" << 'PY'
import sys
import os
import json
import subprocess
import yaml

rules = sys.argv[1].split()
start_iso = sys.argv[2]
end_iso = sys.argv[3]
output_json_path = sys.argv[4]

results = []
window_str = f"{start_iso},{end_iso}"

for rule_path in sorted(rules):
    if not os.path.exists(rule_path):
        continue
    
    # Run 3-sigma_runner.sh with --count-only and --window
    cmd = ["./3-sigma_runner.sh", rule_path, "--count-only", "--window", window_str]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        out_str = res.stdout.strip().split('\n')[-1]
        fp_count = int(out_str) if out_str.isdigit() else 0
    except Exception:
        fp_count = 0

    # Parse metadata from rule YAML
    try:
        with open(rule_path, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f)
        rule_id = data.get('id', 'unknown')
        rule_title = data.get('title', os.path.basename(rule_path))
        level = data.get('level', 'medium')
    except Exception:
        rule_id = 'unknown'
        rule_title = os.path.basename(rule_path)
        level = 'medium'

    fp_rate_per_day = round(fp_count / 7.0, 2)

    results.append({
        "rule_id": rule_id,
        "rule_title": rule_title,
        "level": level,
        "fp_count": fp_count,
        "baseline_window_start": start_iso,
        "baseline_window_end": end_iso,
        "fp_rate_per_day": fp_rate_per_day
    })

# Sort by fp_count descending
results_sorted = sorted(results, key=lambda x: x['fp_count'], reverse=True)

with open(output_json_path, 'w', encoding='utf-8') as f:
    json.dump(results_sorted, f, indent=2)

# Print formatted summary matching expected output style
for r in results_sorted:
    # Find matching filename
    matched_file = ""
    for k in rules:
        try:
            with open(k, 'r', encoding='utf-8') as kf:
                if r['rule_title'] in kf.read():
                    matched_file = os.path.basename(k)
                    break
        except Exception:
            pass
    if not matched_file:
        matched_file = r['rule_title']

    short_name = matched_file.replace('.yml', '').replace('.yaml', '')
    tune_tag = "   [TUNE]" if r['fp_count'] > 10 else ""
    print(f"  {short_name:<30} fp= {r['fp_count']:2d}{tune_tag}")

print(f"{output_json_path} written")
PY
