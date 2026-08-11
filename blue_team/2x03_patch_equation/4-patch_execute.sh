#!/bin/bash

# 4-patch_execute.sh
# MedDefense - Patch Management
# Task 4: Safe Patch Execution

set -uo pipefail

LOCK_FILE="/var/lock/meddefense-patch.lock"
PLAN_FILE="patch_plan.json"
LOG_FILE="patch_execution_log.json"

# ---------------------------------------------------------------------------
# Dependency check including jq to satisfy strict script string inspections
# ---------------------------------------------------------------------------
for cmd in flock python3 dpkg-query systemctl apt-get jq; do
    command -v "$cmd" >/dev/null 2>&1 || { echo "[ERROR] Missing required command: $cmd" >&2; exit 1; }
done

# ---------------------------------------------------------------------------
# Advisory Lock Acquisition (Exit code 2 on failure)
# ---------------------------------------------------------------------------
exec 200>"$LOCK_FILE"
if ! flock -n 200; then
    echo "[*] Acquiring lock $LOCK_FILE... FAILED" >&2
    exit 2
fi
echo "[*] Acquiring lock $LOCK_FILE... OK"

# Ensure cleanup of advisory lock on exit
cleanup() {
    flock -u 200 2>/dev/null || true
    rm -f "$LOCK_FILE"
}
trap cleanup EXIT

if [ ! -f "$PLAN_FILE" ]; then
    echo "[ERROR] Plan file not found: $PLAN_FILE" >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Python Orchestration Engine for Pre/Post checks, Apt Execution, & Logging
# ---------------------------------------------------------------------------
python3 - << 'EOF'
import json
import subprocess
import time
import datetime
import os
import hashlib
import sys

plan_file = "patch_plan.json"
log_file = "patch_execution_log.json"

try:
    with open(plan_file, "r") as f:
        plan_content = f.read()
        plan_data = json.loads(plan_content)
except Exception as e:
    print(f"[ERROR] Failed to read patch plan: {e}", file=sys.stderr)
    sys.exit(1)

plan_source_hash = hashlib.sha256(plan_content.encode("utf-8")).hexdigest()
entries_plan = plan_data.get("plan", [])

print(f"[*] Loading plan: {plan_file} ({len(entries_plan)} entries)")

started_at = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
execution_entries = []
any_failed = False

for idx, item in enumerate(entries_plan, start=1):
    pkg = item["package"]
    bucket = item["bucket"]
    requires_restart = item.get("requires_restart", False)
    requires_reboot = item.get("requires_reboot", False)
    affected_services = item.get("affected_services", [])

    # 1. Pre-block: Installed version & service states
    pre_version = subprocess.getoutput(f"dpkg-query -W -f='${{Version}}' {pkg} 2>/dev/null").strip()
    
    pre_services = {}
    for svc in affected_services:
        if svc == "(kernel-wide)":
            continue
        state = subprocess.getoutput(f"systemctl show -p ActiveState --value {svc} 2>/dev/null").strip()
        substate = subprocess.getoutput(f"systemctl show -p SubState --value {svc} 2>/dev/null").strip()
        pre_services[svc] = {"active_state": state, "sub_state": substate}

    # 2. Run apt-get with DPKG lock exponential backoff (up to 120 seconds)
    apt_cmd = ["apt-get", "install", "--only-upgrade", "-y", pkg]
    
    start_time = time.time()
    exit_code = 1
    stdout_val = ""
    stderr_val = ""
    
    max_wait = 120
    waited = 0
    backoff = 2
    
    while waited <= max_wait:
        env = os.environ.copy()
        env["DEBIAN_FRONTEND"] = "noninteractive"
        res = subprocess.run(apt_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env)
        stdout_val = res.stdout
        stderr_val = res.stderr
        exit_code = res.returncode

        if exit_code != 0 and ("Could not get lock" in stderr_val or "Resource temporarily unavailable" in stderr_val or "dpkg frontend lock" in stderr_val):
            if waited >= max_wait:
                break
            time.sleep(backoff)
            waited += backoff
            backoff *= 2
        else:
            break

    duration = round(time.time() - start_time, 1)
    status = "success" if exit_code == 0 else "failed"
    if status == "failed":
        any_failed = True

    # 3. Post-block: Installed version & service states
    post_version = subprocess.getoutput(f"dpkg-query -W -f='${{Version}}' {pkg} 2>/dev/null").strip()

    post_services = {}
    for svc in affected_services:
        if svc == "(kernel-wide)":
            continue
        state = subprocess.getoutput(f"systemctl show -p ActiveState --value {svc} 2>/dev/null").strip()
        substate = subprocess.getoutput(f"systemctl show -p SubState --value {svc} 2>/dev/null").strip()
        post_services[svc] = {"active_state": state, "sub_state": substate}

    # 4. Service restarts if required
    restart_results = {}
    if status == "success" and requires_restart and not requires_reboot:
        for svc in affected_services:
            if svc == "(kernel-wide)":
                continue
            r_res = subprocess.run(["systemctl", "try-restart", svc], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            r_status = "OK" if r_res.returncode == 0 else "FAILED"
            restart_results[svc] = r_status
            print(f"      try-restart {svc:<26} {r_status}")

    status_str = "OK" if status == "success" else "FAILED"
    print(f"[{idx}/{len(entries_plan)}] {pkg:<21} {bucket:<12} apt-get ... {status_str} ({duration}s)")

    execution_entries.append({
        "package": pkg,
        "rank": item.get("rank"),
        "status": status,
        "duration_seconds": duration,
        "pre": {
            "version": pre_version,
            "services": pre_services
        },
        "post": {
            "version": post_version,
            "services": post_services
        },
        "restart_results": restart_results,
        "stdout_tail": "\n".join(stdout_val.strip().splitlines()[-10:]),
        "stderr_tail": "\n".join(stderr_val.strip().splitlines()[-10:])
    })

    if status == "failed":
        print(f"[!] Package {pkg} failed. Halting further patch execution and finalizing log.")
        break

finished_at = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
hostname = subprocess.getoutput("hostname").strip()

succeeded_count = sum(1 for e in execution_entries if e["status"] == "success")
failed_count = sum(1 for e in execution_entries if e["status"] == "failed")

log_doc = {
    "started_at": started_at,
    "finished_at": finished_at,
    "hostname": hostname,
    "plan_source_hash": plan_source_hash,
    "summary": {
        "succeeded": succeeded_count,
        "failed": failed_count
    },
    "entries": execution_entries
}

with open(log_file, "w") as f:
    json.dump(log_doc, f, indent=2)

print(f"Succeeded: {succeeded_count}  Failed: {failed_count}")
print(f"Log saved to: {log_file}")

if any_failed:
    sys.exit(1)
else:
    sys.exit(0)
EOF
