#!/bin/bash
set -euo pipefail

RULES_DIR="rules/sigma"
TUNED_DIR="rules/sigma/tuned"
OUTPUT_JSON="rule_quality.json"

BASELINE_PKG_DIR="${BASELINE_PKG:-$HOME/3x01_reading_the_noise}"
if [[ ! -d "$BASELINE_PKG_DIR" ]]; then
    BASELINE_PKG_DIR="/home/student/3x01_reading_the_noise"
fi

ANOMALIES_FILE="$BASELINE_PKG_DIR/anomalies/ranked_anomalies.json"
LABELED_FILE="$BASELINE_PKG_DIR/taxonomy/labeled_events.json"

python3 - "$RULES_DIR" "$TUNED_DIR" "$OUTPUT_JSON" "$ANOMALIES_FILE" "$LABELED_FILE" << 'PY'
import sys
import os
import json
import subprocess
import yaml

rules_dir = sys.argv[1]
tuned_dir = sys.argv[2]
output_json = sys.argv[3]
anomalies_file = sys.argv[4]
labeled_file = sys.argv[5]

fp_data = {}
if os.path.exists("fp_baseline.json"):
    with open("fp_baseline.json", "r", encoding="utf-8") as f:
        for item in json.load(f):
            fp_data[item["rule_title"]] = item["fp_count"]

tp_refs = set()
if os.path.exists(anomalies_file):
    try:
        with open(anomalies_file, "r", encoding="utf-8") as f:
            data = json.load(f)
            for item in data:
                if isinstance(item, dict):
                    ref = item.get("event_ref") or item.get("id") or item.get("timestamp")
                    if ref:
                        tp_refs.add(str(ref))
    except Exception:
        pass

if os.path.exists(labeled_file):
    try:
        with open(labeled_file, "r", encoding="utf-8") as f:
            data = json.load(f)
            for item in data:
                if isinstance(item, dict):
                    if item.get("is_malicious") or item.get("label") == "malicious":
                        ref = item.get("event_ref") or item.get("id") or item.get("timestamp")
                        if ref:
                            tp_refs.add(str(ref))
    except Exception:
        pass

total_gt_count = max(len(tp_refs), 10)

rule_paths = []
for d in [rules_dir, tuned_dir]:
    if os.path.exists(d):
        for root, _, files in os.walk(d):
            for file in files:
                if file.endswith(('.yml', '.yaml')):
                    rule_paths.append(os.path.join(root, file))

print(f"evaluating {len(rule_paths)} rules against labeled ground truth")

results = []
for rule_path in sorted(rule_paths):
    try:
        with open(rule_path, "r", encoding="utf-8") as f:
            rule_content = yaml.safe_load(f)
    except Exception:
        continue
    
    rule_title = rule_content.get("title", os.path.basename(rule_path))
    rule_id = rule_content.get("id", "unknown")
    level = rule_content.get("level", "medium")

    cmd = ["./3-sigma_runner.sh", rule_path]
    tp_count = 0
    matched_events = []
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        if res.returncode == 0 and res.stdout.strip():
            out_json = json.loads(res.stdout.strip())
            matched_events = out_json.get("matches", [])
    except Exception:
        pass

    for ev in matched_events:
        ref = str(ev.get("event_ref") or ev.get("timestamp") or "")
        if ref and ref in tp_refs:
            tp_count += 1

    base_fp = fp_data.get(rule_title, max(0, len(matched_events) - tp_count))
    fp_count = base_fp
    fn_count = max(0, total_gt_count - tp_count)

    precision = tp_count / (tp_count + fp_count) if (tp_count + fp_count) > 0 else 0.0
    recall = tp_count / (tp_count + fn_count) if (tp_count + fn_count) > 0 else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0

    results.append({
        "rule_id": rule_id,
        "rule_title": rule_title,
        "level": level,
        "tp_count": tp_count,
        "fp_count": fp_count,
        "fn_count": fn_count,
        "precision": round(precision, 2),
        "recall": round(recall, 2),
        "f1": round(f1, 2)
    })

results_sorted = sorted(results, key=lambda x: (x["f1"], x["precision"], x["recall"]), reverse=True)

with open(output_json, "w", encoding="utf-8") as f:
    json.dump(results_sorted, f, indent=2)

print("strongest")
for r in results_sorted[:min(5, len(results_sorted))]:
    matched_file = ""
    for k in rule_paths:
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
    marker = "  [STRONG]" if r['f1'] >= 0.7 else ("  [WEAK]" if r['f1'] < 0.3 else "")
    print(f"  {short_name:<30} f1={r['f1']:.2f}  p={r['precision']:.2f} r={r['recall']:.2f}{marker}")

if len(results_sorted) > 5:
    print("weakest")
    for r in results_sorted[-min(3, len(results_sorted)):]:
        matched_file = ""
        for k in rule_paths:
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
        marker = "  [STRONG]" if r['f1'] >= 0.7 else ("  [WEAK]" if r['f1'] < 0.3 else "")
        print(f"  {short_name:<30} f1={r['f1']:.2f}  p={r['precision']:.2f} r={r['recall']:.2f}{marker}")

print(f"{output_json} written")
PY
