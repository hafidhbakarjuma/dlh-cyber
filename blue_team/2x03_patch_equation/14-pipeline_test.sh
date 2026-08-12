#!/bin/bash

# 14-pipeline_test.sh
# MedDefense - Patch Management
# Task 14: The Pipeline Test Against a Simulated Advisory

set -uo pipefail

OUTPUT_FILE="pipeline_test_results.json"
FEED_FILE="cve_feed.json"
BACKUP_FILE="cve_feed.json.bak"
SIMULATED_FILE="cve_feed.simulated.json"
EXPECTED_PLAN_FILE="patch_plan.expected.json"
PRODUCED_PLAN_FILE="patch_plan.json"
PIPELINE_SCRIPT="./13-patch_pipeline.sh"

# Dependency checks
for cmd in python3 jq; do
    command -v "$cmd" >/dev/null 2>&1 || { echo "[ERROR] Missing required command: $cmd" >&2; exit 1; }
done

echo "[*] Scenario: simulated CVE advisory"

# Ensure simulated feed and expected plan exist or create mock defaults if testing locally
if [ ! -f "$SIMULATED_FILE" ]; then
    echo "[WARNING] $SIMULATED_FILE not found, creating a fallback simulated feed..." >&2
    echo '{"cves": [{"cve": "CVE-2024-SIMULATED", "package": "openssh-server", "cvss": 9.8}]}' > "$SIMULATED_FILE"
fi

if [ ! -f "$EXPECTED_PLAN_FILE" ]; then
    echo "[WARNING] $EXPECTED_PLAN_FILE not found, creating a fallback expected plan..." >&2
    echo '{"plan": []}' > "$EXPECTED_PLAN_FILE"
fi

# 1. Back up current cve_feed.json
if [ -f "$FEED_FILE" ]; then
    cp "$FEED_FILE" "$BACKUP_FILE"
    echo "[*] Backing up cve_feed.json...              OK"
else
    touch "$BACKUP_FILE"
fi

# 2. Inject simulated feed
cp "$SIMULATED_FILE" "$FEED_FILE"
echo "[*] Injecting cve_feed.simulated.json...     OK"

# 3. Invoke pipeline with PIPELINE_TEST=1
echo "[*] Running pipeline (PIPELINE_TEST=1)..."
export PIPELINE_TEST=1
STARTED_AT=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

PIPELINE_EXIT=0
if [ -x "$PIPELINE_SCRIPT" ]; then
    "$PIPELINE_SCRIPT" || PIPELINE_EXIT=$?
else
    bash "$PIPELINE_SCRIPT" || PIPELINE_EXIT=$?
fi

FINISHED_AT=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

# 4. Restore original cve_feed.json immediately
if [ -f "$BACKUP_FILE" ]; then
    mv "$BACKUP_FILE" "$FEED_FILE"
    echo "[*] Restoring cve_feed.json...                OK"
fi

# ---------------------------------------------------------------------------
# Python Plan Comparison & Verification Engine
# ---------------------------------------------------------------------------
python3 - << EOF
import json
import os
import difflib
import sys

produced_path = "$PRODUCED_PLAN_FILE"
expected_path = "$EXPECTED_PLAN_FILE"
result_path = "$OUTPUT_FILE"
pipeline_exit = $PIPELINE_EXIT

plan_matches = False
diff_result = []

def normalize_json(data):
    # Recursively remove or replace timestamps / variable fields for normalization
    if isinstance(data, dict):
        new_dict = {}
        for k, v in data.items():
            if "timestamp" in k.lower() or "date" in k.lower() or "started" in k.lower() or "finished" in k.lower():
                new_dict[k] = "NORMALIZED_TIMESTAMP"
            else:
                new_dict[k] = normalize_json(v)
        return new_dict
    elif isinstance(data, list):
        return [normalize_json(item) for item in data]
    else:
        return data

try:
    if os.path.exists(produced_path) and os.path.exists(expected_path):
        with open(produced_path, "r") as f1, open(expected_path, "r") as f2:
            prod_data = json.load(f1)
            exp_data = json.load(f2)
            
            norm_prod = json.dumps(normalize_json(prod_data), sort_keys=True, indent=2)
            norm_exp = json.dumps(normalize_json(exp_data), sort_keys=True, indent=2)
            
            if norm_prod == norm_exp:
                plan_matches = True
                print("[*] Comparing patch_plan.json to expected...  match")
            else:
                print("[*] Comparing patch_plan.json to expected...  mismatch")
                diff = list(difflib.unified_diff(
                    norm_exp.splitlines(),
                    norm_prod.splitlines(),
                    fromfile="expected",
                    tofile="produced",
                    lineterm=""
                ))
                diff_result = diff
    else:
        print("[*] Plan files missing for comparison.")
except Exception as e:
    print(f"[ERROR] Comparison failed: {e}")

# Check pipeline artifacts
pipeline_run_path = "pipeline_run.json"
stages_ok = False
artifacts_valid = True

if os.path.exists(pipeline_run_path):
    try:
        with open(pipeline_run_path, "r") as prf:
            pr_data = json.load(prf)
            if pr_data.get("pipeline_status") in ["ok", "deferred"]:
                stages_ok = True
            for stage in pr_data.get("stages", []):
                art_path = pr_data.get("artifacts", {}).get(stage.get("stage"))
                if art_path and os.path.exists(art_path):
                    if os.path.getsize(art_path) == 0:
                        artifacts_valid = False
    except Exception:
        artifacts_valid = False

verdict = "pass" if (pipeline_exit == 0 and plan_matches and stages_ok and artifacts_valid) else "fail"

result_report = {
    "scenario": "simulated CVE advisory",
    "started_at": "$STARTED_AT",
    "finished_at": "$FINISHED_AT",
    "stages_ok": stages_ok,
    "plan_matches_expected": plan_matches,
    "diff": diff_result,
    "verdict": verdict
}

with open(result_path, "w") as rf:
    json.dump(result_report, rf, indent=2)

print(f"VERDICT: {verdict}")
print(f"Report saved to: {result_path}")

if verdict == "pass":
    sys.exit(0)
else:
    sys.exit(1)
EOF
