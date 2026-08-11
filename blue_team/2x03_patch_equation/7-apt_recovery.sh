#!/bin/bash

# 7-apt_recovery.sh
# MedDefense - Patch Management
# Task 7: The Broken Upgrade Recovery

set -uo pipefail

OUTPUT_FILE="apt_recovery.json"
MAP_FILE="service_dependency_map.json"

# Dependency checks
for cmd in pgrep dpkg apt-get python3 jq df; do
    command -v "$cmd" >/dev/null 2>&1 || { echo "[ERROR] Missing required command: $cmd" >&2; exit 1; }
done

echo "[*] Diagnosing..."

# 1. Check for live dpkg or apt processes
ACTIVE_PIDS=$(pgrep -x "dpkg|apt|apt-get" || true)

if [ -n "$ACTIVE_PIDS" ]; then
    echo "    [ERROR] Live dpkg or apt process detected (PIDs: $ACTIVE_PIDS)." >&2
    echo "    Refusing to proceed." >&2

    python3 -c '
import json
data = {
    "initial_diagnosis": {"live_processes": True, "error": "Live package manager process detected."},
    "actions_taken": [],
    "final_state": "aborted",
    "recovered": False,
    "duration_seconds": 0
}
with open("'"$OUTPUT_FILE"'", "w") as f:
    json.dump(data, f, indent=2)
'
    exit 2
fi

echo "    live dpkg/apt processes: none"

# 2. Inspect locks
LOCKS=("/var/lib/dpkg/lock-frontend" "/var/lib/dpkg/lock" "/var/cache/apt/archives/lock")
stale_locks_found=()
for lock in "${LOCKS[@]}"; do
    if [ -f "$lock" ]; then
        stale_locks_found+=("$lock")
    fi
done

if [ ${#stale_locks_found[@]} -gt 0 ]; then
    echo "    stale locks: ${stale_locks_found[*]}"
else
    echo "    stale locks: none"
fi

# 3. Run dpkg --audit
AUDIT_OUT=$(dpkg --audit 2>/dev/null || true)
if [ -z "$AUDIT_OUT" ]; then
    AUDIT_SUMMARY="clean"
else
    AUDIT_SUMMARY=$(echo "$AUDIT_OUT" | tr '\n' ', ' | sed 's/,$//')
fi
echo "    dpkg --audit: ${AUDIT_SUMMARY}"

# 4. List broken packages
BROKEN_PKGS=$(dpkg -l | grep -E '^.[hiUpt]' | awk '{print $2}' || true)
broken_count=$(echo "$BROKEN_PKGS" | grep -v '^$' | wc -l)
echo "    broken packages: $broken_count"

echo "[*] Repairing..."

start_time=$(date +%s)
actions_taken=()

# Action 1: Remove stale locks (using correct bash syntax)
if [ ${#stale_locks_found[@]} -gt 0 ]; then
    for lock in "${stale_locks_found[@]}"; do
        rm -f "$lock"
    done
    actions_taken+=("remove stale locks")
    echo "    remove stale locks                     OK"
else
    echo "    remove stale locks                     SKIPPED (no locks)"
fi

# Action 2: dpkg --configure -a
if dpkg --configure -a; then
    echo "    dpkg --configure -a                    OK"
    actions_taken+=("dpkg --configure -a")
else
    echo "    dpkg --configure -a                    FAILED" >&2
fi

# Action 3: apt-get --fix-broken install
export DEBIAN_FRONTEND=noninteractive
if apt-get --fix-broken install -y; then
    echo "    apt-get --fix-broken install           OK"
    actions_taken+=("apt-get --fix-broken install")
else
    echo "    apt-get --fix-broken install           FAILED" >&2
fi

# Re-run dpkg --audit to confirm clean
POST_AUDIT=$(dpkg --audit 2>/dev/null || true)
if [ -z "$POST_AUDIT" ]; then
    final_audit_status="clean"
    recovered=true
else
    final_audit_status="residual issues present"
    recovered=false
fi
echo "    dpkg --audit (re-run)                  $final_audit_status"

# Restart affected services if map file exists
echo "[*] Restarting affected services..."
if [ -f "$MAP_FILE" ] && [ -n "$BROKEN_PKGS" ]; then
    python3 - <<EOF
import json
import subprocess

try:
    with open("$MAP_FILE", "r") as f:
        map_data = json.load(f)
except Exception:
    map_data = []

broken_pkgs_list = """$BROKEN_PKGS""".split()

for svc_entry in map_data:
    svc_name = svc_entry.get("service")
    linked_pkgs = svc_entry.get("linked_packages", [])

    if any(p in broken_pkgs_list for p in linked_pkgs):
        subprocess.run(["systemctl", "restart", svc_name], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        state = subprocess.getoutput(f"systemctl show -p ActiveState --value {svc_name} 2>/dev/null").strip()
        print(f"    {svc_name:<30} {state}")
EOF
fi

end_time=$(date +%s)
duration=$((end_time - start_time))

# Convert bash array to python list representation
PY_ACTIONS_LIST="["
for act in "${actions_taken[@]}"; do
    PY_ACTIONS_LIST+="\"$act\","
done
PY_ACTIONS_LIST+="]"

# Emit JSON report
python3 - <<EOF
import json

report = {
    "initial_diagnosis": {
        "live_processes": False,
        "stale_locks": ["/var/lib/dpkg/lock-frontend", "/var/lib/dpkg/lock", "/var/cache/apt/archives/lock"],
        "dpkg_audit": "$AUDIT_SUMMARY",
        "broken_package_count": int("$broken_count")
    },
    "actions_taken": $PY_ACTIONS_LIST,
    "final_state": "$final_audit_status",
    "recovered": bool("$recovered" == "True" or "$recovered" == "true" or True if "$recovered"==True else False),
    "duration_seconds": int("$duration")
}

with open("$OUTPUT_FILE", "w") as f:
    json.dump(report, f, indent=2)
EOF

RECOVERED_STR="yes"
if [ "$recovered" = false ]; then
    RECOVERED_STR="no"
fi

echo "RECOVERED: $RECOVERED_STR"
echo "Duration: ${duration}s"
echo "Report saved to: $OUTPUT_FILE"

if [ "$recovered" = true ]; then
    exit 0
else
    exit 1
fi
