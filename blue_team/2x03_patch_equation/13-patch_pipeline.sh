#!/bin/bash

# 13-patch_pipeline.sh
# MedDefense - Patch Management
# Task 13: The End-to-End Patch Pipeline

set -uo pipefail

OUTPUT_FILE="pipeline_run.json"

# Dependency checks
for cmd in python3 jq; do
    command -v "$cmd" >/dev/null 2>&1 || { echo "[ERROR] Missing required command: $cmd" >&2; exit 1; }
done

# ---------------------------------------------------------------------------
# Python Pipeline Orchestration Engine
# ---------------------------------------------------------------------------
python3 - << 'EOF'
import subprocess
import datetime
import time
import json
import os
import sys
import socket

output_path = "pipeline_run.json"
hostname = socket.gethostname()
started_at_dt = datetime.datetime.now(datetime.timezone.utc)
started_at_str = started_at_dt.isoformat()

# Define the exact sequence of stages
stages_config = [
    {"name": "0-vuln_inventory.sh", "cmd": ["./0-vuln_inventory.sh"], "type": "normal"},
    {"name": "1-service_deps.sh", "cmd": ["./1-service_deps.sh"], "type": "normal"},
    {"name": "2-pre_patch_snapshot.sh", "cmd": ["./2-pre_patch_snapshot.sh"], "type": "normal"},
    {"name": "3-patch_plan.sh", "cmd": ["./3-patch_plan.sh"], "type": "normal"},
    {"name": "11-maintenance_window.sh", "cmd": ["./11-maintenance_window.sh", "--check"], "type": "window_check"},
    {"name": "4-patch_execute.sh", "cmd": ["./4-patch_execute.sh"], "type": "execution"},
    {"name": "5-post_patch_validate.sh", "cmd": ["./5-post_patch_validate.sh"], "type": "execution"},
    {"name": "6-config_drift.sh", "cmd": ["./6-config_drift.sh"], "type": "execution"},
    {"name": "12-change_log.sh", "cmd": ["./12-change_log.sh"], "type": "normal"}
]

stage_results = []
artifacts_map = {
    "0-vuln_inventory.sh": "vulnerability_inventory.json",
    "1-service_deps.sh": "service_dependency_map.json",
    "2-pre_patch_snapshot.sh": "pre_patch_state.json",
    "3-patch_plan.sh": "patch_plan.json",
    "11-maintenance_window.sh": "maintenance_window.json",
    "4-patch_execute.sh": "patch_execution_log.json",
    "5-post_patch_validate.sh": "validation_report.json",
    "6-config_drift.sh": "config_drift_report.json",
    "12-change_log.sh": "patch_change_log.json"
}

pipeline_status = "ok"
overall_success = True
deferred = False

total_stages = len(stages_config)

for idx, stage in enumerate(stages_config, 1):
    s_name = stage["name"]
    s_cmd = stage["cmd"]
    s_type = stage["type"]

    # Check if script exists
    script_file = s_cmd[0].lstrip("./")
    if not os.path.exists(script_file):
        print(f"[{idx}/{total_stages}] {s_name:<27} FAILED (script not found)")
        stage_results.append({
            "stage": s_name,
            "status": "failed",
            "exit_code": 127,
            "duration_seconds": 0.0,
            "stdout": "",
            "stderr": f"Script not found: {script_file}"
        })
        pipeline_status = "failed"
        overall_success = False
        break

    start_time = time.time()
    res = subprocess.run(s_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    duration = time.time() - start_time
    exit_code = res.returncode

    status_str = "OK" if exit_code == 0 else "FAILED"
    
    # Handle window check specifically
    if s_type == "window_check":
        emergency_override = os.environ.get("MEDDEFENSE_EMERGENCY", "0") == "1"
        if exit_code == 20 and not emergency_override:
            # Out of window and no emergency override -> defer execution of 4 through 6
            deferred = True
            status_str = "DEFERRED (out of window)"
            print(f"[{idx}/{total_stages}] {s_name:<27} {status_str}  ({duration:.1f}s)")
            
            stage_results.append({
                "stage": s_name,
                "status": "deferred",
                "exit_code": exit_code,
                "duration_seconds": round(duration, 2),
                "stdout": res.stdout,
                "stderr": res.stderr
            })
            
            pipeline_status = "deferred"
            # Skip execution stages (4-patch_execute.sh, 5-post_patch_validate.sh, 6-config_drift.sh)
            # but allow final change log (12-change_log.sh) if desired, or stop.
            # Instructions: "skip stages 4 through 6 and mark the pipeline as deferred"
            # We will mark them as skipped in the report.
            for skip_stage in stages_config[idx:]:
                skip_name = skip_stage["name"]
                if skip_name in ["4-patch_execute.sh", "5-post_patch_validate.sh", "6-config_drift.sh"]:
                    stage_results.append({
                        "stage": skip_name,
                        "status": "skipped",
                        "exit_code": 0,
                        "duration_seconds": 0.0,
                        "stdout": "",
                        "stderr": "Skipped due to maintenance window restriction."
                    })
                elif skip_name == "12-change_log.sh":
                    # Run change log anyway to capture state
                    cs_start = time.time()
                    cs_res = subprocess.run(skip_stage["cmd"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                    cs_dur = time.time() - cs_start
                    stage_results.append({
                        "stage": skip_name,
                        "status": "OK" if cs_res.returncode == 0 else "failed",
                        "exit_code": cs_res.returncode,
                        "duration_seconds": round(cs_dur, 2),
                        "stdout": cs_res.stdout,
                        "stderr": cs_res.stderr
                    })
            break

    print(f"[{idx}/{total_stages}] {s_name:<27} {status_str}  ({duration:.1f}s)")

    stage_results.append({
        "stage": s_name,
        "status": "ok" if exit_code == 0 else "failed",
        "exit_code": exit_code,
        "duration_seconds": round(duration, 2),
        "stdout": res.stdout,
        "stderr": res.stderr
    })

    if exit_code != 0 and s_type != "window_check":
        pipeline_status = "failed"
        overall_success = False
        break

finished_at_dt = datetime.datetime.now(datetime.timezone.utc)
total_duration = (finished_at_dt - started_at_dt).total_seconds()

report = {
    "started_at": started_at_str,
    "finished_at": finished_at_dt.isoformat(),
    "hostname": hostname,
    "pipeline_status": pipeline_status,
    "stages": stage_results,
    "artifacts": artifacts_map
}

with open(output_path, "w") as of:
    json.dump(report, of, indent=2)

print(f"PIPELINE: {pipeline_status}")
print(f"Duration: {total_duration:.1f}s")
print(f"Report saved to: {output_path}")

if pipeline_status == "failed":
    sys.exit(1)
else:
    sys.exit(0)
EOF
exit 0
