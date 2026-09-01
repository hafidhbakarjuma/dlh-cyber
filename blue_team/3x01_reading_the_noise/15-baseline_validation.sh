#!/bin/bash
set -euo pipefail

# Ensure baseline summary exists
if [ ! -f "baseline_summary.json" ]; then
    echo "Error: baseline_summary.json not found. Run Task 9 first." >&2
    exit 1
fi

# Backup original summary
cp baseline_summary.json baseline_summary_orig.json

# 1. Run Self-Check (Evaluation window set to baseline window itself)
python3 - << 'PY_SETUP'
import json

with open("baseline_summary.json", "r") as f:
    data = json.load(f)

# Override evaluation window with baseline window bounds
data["evaluation_window"] = data.get("baseline_window", {})

with open("baseline_summary.json", "w") as f:
    json.dump(data, f, indent=2)
PY_SETUP

# Run anomaly scripts for self-check
./10-anomalies_auth.sh >/dev/null 2>&1 || true
./11-anomalies_process.sh >/dev/null 2>&1 || true
./12-anomalies_network.sh >/dev/null 2>&1 || true

# Save self-check results
[ -f "anomalies_auth.json" ] && cp anomalies_auth.json self_check_auth.json
[ -f "anomalies_process.json" ] && cp anomalies_process.json self_check_process.json
[ -f "anomalies_network.json" ] && cp anomalies_network.json self_check_network.json

# Restore original baseline summary
cp baseline_summary_orig.json baseline_summary.json

# 2. Run Live-Check (Normal evaluation window)
./10-anomalies_auth.sh >/dev/null 2>&1 || true
./11-anomalies_process.sh >/dev/null 2>&1 || true
./12-anomalies_network.sh >/dev/null 2>&1 || true

# Save live-check results
[ -f "anomalies_auth.json" ] && cp anomalies_auth.json live_check_auth.json
[ -f "anomalies_process.json" ] && cp anomalies_process.json live_check_process.json
[ -f "anomalies_network.json" ] && cp anomalies_network.json live_check_network.json

# 3. Compute Metrics and Verdict
python3 - << 'PY_EVAL'
import json
import os

def load_json_list(filename):
    if os.path.exists(filename):
        try:
            with open(filename, 'r') as f:
                d = json.load(f)
                if isinstance(d, list):
                    return d
        except:
            pass
    return []

self_auth = load_json_list("self_check_auth.json")
self_proc = load_json_list("self_check_process.json")
self_net = load_json_list("self_check_network.json")

live_auth = load_json_list("live_check_auth.json")
live_proc = load_json_list("live_check_process.json")
live_net = load_json_list("live_check_network.json")

self_all = self_auth + self_proc + self_net
live_all = live_auth + live_proc + live_net

self_check_total = len(self_all)
live_check_total = len(live_all)

def get_breakdown(items):
    bd = {}
    for item in items:
        t = item.get("anomaly_type", "unknown")
        bd[t] = bd.get(t, 0) + 1
    return bd

self_breakdown = get_breakdown(self_all)
live_breakdown = get_breakdown(live_all)

# Signal-to-noise ratio calculation
signal_to_noise_ratio = live_check_total / max(self_check_total, 1)

# Verdict criteria: self_check_total < 5 and SNR >= 3.0
acceptable_threshold = 5
passed = (self_check_total < acceptable_threshold) and (signal_to_noise_ratio >= 3.0)
verdict = "pass" if passed else "fail"

validation_data = {
    "self_check_total": self_check_total,
    "live_check_total": live_check_total,
    "signal_to_noise_ratio": round(signal_to_noise_ratio, 2),
    "self_check_breakdown": self_breakdown,
    "live_check_breakdown": live_breakdown,
    "verdict": verdict
}

with open("baseline_validation.json", "w") as f:
    json.dump(validation_data, f, indent=2)

print(f"self-check anomalies (baseline window): {self_check_total}")
print(f"live-check anomalies (evaluation win ): {live_check_total}")
print(f"signal-to-noise ratio                : {round(signal_to_noise_ratio, 2)}")
print(f"verdict                              : {verdict}")
print("baseline_validation.json written")

if not passed:
    exit(1)
PY_EVAL
