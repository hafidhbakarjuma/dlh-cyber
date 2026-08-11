#!/bin/bash

# 3-patch_plan.sh
# MedDefense - Patch Management
# Task 3: The Patch Plan

set -uo pipefail

VULN_FILE="vulnerability_inventory.json"
MAP_FILE="service_dependency_map.json"
OUTPUT_FILE="patch_plan.json"

# Scoring Weights Constants
CVSS_WEIGHT="0.5"
KEV_WEIGHT="3.0"
CRITICALITY_WEIGHT="1.5"
EXPOSURE_WEIGHT="1.0"

for f in "$VULN_FILE" "$MAP_FILE"; do
    if [ ! -f "$f" ]; then
        echo "[ERROR] Required input file not found: $f" >&2
        exit 1
    fi
    if [ ! -s "$f" ]; then
        echo "[ERROR] Input file is empty (0 bytes): $f. Please re-generate it." >&2
        exit 1
    fi
done

echo "[INFO] Generating prioritized patch plan..."

python3 - <<EOF
import json
import sys

cvss_w = float("$CVSS_WEIGHT")
kev_w = float("$KEV_WEIGHT")
crit_w = float("$CRITICALITY_WEIGHT")
exposure_w = float("$EXPOSURE_WEIGHT")

try:
    with open("$VULN_FILE", "r") as f:
        vuln_data = json.load(f)
except Exception as e:
    print(f"[ERROR] Failed to parse $VULN_FILE: {e}", file=sys.stderr)
    sys.exit(1)

try:
    with open("$MAP_FILE", "r") as f:
        map_data = json.load(f)
except Exception as e:
    print(f"[ERROR] Failed to parse $MAP_FILE: {e}", file=sys.stderr)
    sys.exit(1)

crit_scores = {
    "critical": 4.0,
    "high": 3.0,
    "medium": 2.0,
    "low": 1.0,
    "unknown": 1.0
}

pkg_to_services = {}
service_criticalities = {}

for svc_entry in map_data:
    svc_name = svc_entry.get("service")
    crit = svc_entry.get("criticality", "low").lower()
    service_criticalities[svc_name] = crit

    for pkg in svc_entry.get("linked_packages", []):
        if pkg not in pkg_to_services:
            pkg_to_services[pkg] = []
        if svc_name not in pkg_to_services[pkg]:
            pkg_to_services[pkg].append(svc_name)

packages = vuln_data.get("packages", [])
plan_entries = []

for item in packages:
    pkg = item.get("package")
    max_cvss = item.get("max_cvss")
    max_cvss = 0.0 if max_cvss is None else float(max_cvss)

    in_kev = item.get("in_cisa_kev", False)
    kev_val = 1.0 if in_kev else 0.0

    affected_svcs = pkg_to_services.get(pkg, [])
    is_kernel_or_systemd = any(k in pkg for k in ["linux-image", "kernel", "systemd"])

    if is_kernel_or_systemd and not affected_svcs:
        affected_svcs = ["(kernel-wide)"]

    max_crit_score = 1.0
    for svc in affected_svcs:
        if svc == "(kernel-wide)":
            max_crit_score = 4.0
            break
        c_label = service_criticalities.get(svc, "low")
        c_score = crit_scores.get(c_label, 1.0)
        if c_score > max_crit_score:
            max_crit_score = c_score

    exposure_rank = 1.0
    if affected_svcs and "(kernel-wide)" not in affected_svcs:
        exposure_rank = float(len(affected_svcs))

    score = round((cvss_w * max_cvss) + (kev_w * kev_val) + (crit_w * max_crit_score) + (exposure_w * exposure_rank), 2)

    if score >= 7.0:
        bucket = "emergency"
    elif score >= 4.0:
        bucket = "urgent"
    else:
        bucket = "scheduled"

    plan_entries.append({
        "package": pkg,
        "score": score,
        "bucket": bucket,
        "affected_services": affected_svcs,
        "requires_restart": bool(affected_svcs),
        "requires_reboot": is_kernel_or_systemd,
        "rollback_target_version": item.get("installed_version"),
        "_raw_cvss": max_cvss
    })

plan_entries.sort(key=lambda x: (x["score"], x["_raw_cvss"]), reverse=True)

final_plan = []
for idx, entry in enumerate(plan_entries, start=1):
    entry["rank"] = idx
    del entry["_raw_cvss"]
    final_plan.append(entry)

counts = {"emergency": 0, "urgent": 0, "scheduled": 0}
reboot_needed_by_plan = False

for entry in final_plan:
    counts[entry["bucket"]] += 1
    if entry["requires_reboot"]:
        reboot_needed_by_plan = True

output_doc = {
    "generated_at": vuln_data.get("generated_at"),
    "weights": {
        "cvss_weight": cvss_w,
        "kev_weight": kev_w,
        "criticality_weight": crit_w,
        "exposure_weight": exposure_w
    },
    "summary": {
        "emergency": counts["emergency"],
        "urgent": counts["urgent"],
        "scheduled": counts["scheduled"],
        "reboot_required": reboot_needed_by_plan
    },
    "plan": final_plan
}

with open("$OUTPUT_FILE", "w") as f:
    json.dump(output_doc, f, indent=2)

print(f"Emergency: {counts['emergency']}   Urgent: {counts['urgent']}   Scheduled: {counts['scheduled']}")
reboot_str = "yes (kernel update present)" if reboot_needed_by_plan else "no"
print(f"Reboot required by plan: {reboot_str}")
print(f"Report saved to: $OUTPUT_FILE")
EOF
