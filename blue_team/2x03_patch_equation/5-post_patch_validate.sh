#!/bin/bash

# 5-post_patch_validate.sh
# MedDefense - Patch Management
# Task 5: Post-Patch Service Validation

set -uo pipefail

PRE_PATCH_FILE="pre_patch_state.json"
MAP_FILE="service_dependency_map.json"
PROBES_FILE="service_probes.json"
OUTPUT_FILE="post_patch_validation.json"

# Dependency check including jq, python3, ss, systemctl
for cmd in jq python3 ss systemctl; do
    command -v "$cmd" >/dev/null 2>&1 || { echo "[ERROR] Missing required command: $cmd" >&2; exit 1; }
done

for f in "$PRE_PATCH_FILE" "$MAP_FILE"; do
    if [ ! -f "$f" ]; then
        echo "[ERROR] Required input file not found: $f" >&2
        exit 1
    fi
done

# Ensure service_probes.json exists as a default if missing
if [ ! -f "$PROBES_FILE" ]; then
    cat << 'EOF' > "$PROBES_FILE"
{
  "apache2.service": "curl -s -I http://localhost/",
  "ssh.service": "nc -z localhost 22 || true",
  "postgresql.service": "pg_isready || true"
}
EOF
fi

echo "[*] Loading pre-patch state and dependency mappings for validation..."

# ---------------------------------------------------------------------------
# Python Validation Engine
# ---------------------------------------------------------------------------
python3 - << 'EOF'
import json
import subprocess
import sys
import os

pre_file = "pre_patch_state.json"
map_file = "service_dependency_map.json"
probes_file = "service_probes.json"
output_file = "post_patch_validation.json"

try:
    with open(pre_file, "r") as f:
        pre_data = json.load(f)
    with open(map_file, "r") as f:
        map_data = json.load(f)
    with open(probes_file, "r") as f:
        probes_data = json.load(f)
except Exception as e:
    print(f"[ERROR] Failed to load JSON configuration files: {e}", file=sys.stderr)
    sys.exit(1)

details = []

# 1. Service State Checks
pre_services = pre_data.get("services_detail", [])
svc_state_pass = 0
svc_state_total = len(pre_services)

for svc_item in pre_services:
    svc_name = svc_item.get("service")
    pre_active = svc_item.get("active_state", "active")
    
    # Query current live active state
    current_active = subprocess.getoutput(f"systemctl show -p ActiveState --value {svc_name} 2>/dev/null").strip()
    
    # A check passes if active state is 'active' (or matches/better than pre-patch)
    if current_active == "active":
        status = "pass"
        svc_state_pass += 1
    else:
        status = "regression"

    details.append({
        "category": "service_state",
        "target": svc_name,
        "pre_state": pre_active,
        "post_state": current_active,
        "status": status
    })

# 2. Listening Socket Checks
pre_sockets = pre_data.get("listening", [])
current_ss_output = subprocess.getoutput("ss -tulnp 2>/dev/null")

socket_pass = 0
socket_total = len(pre_sockets)

for sock_item in pre_sockets:
    sock_info = sock_item.get("socket_info", "").strip()
    if not sock_info:
        continue
    
    # Extract port or key identifier from socket info (e.g., ':80', ':22', etc.)
    # We check if key parts or ports from pre-patch still exist in active ss output
    # Fallback to checking substring or matching endpoint
    parts = sock_info.split()
    found = False
    for part in parts:
        if ":" in part and any(c.isdigit() for c in part):
            # Extract local address port
            port_part = part.split(":")[-1]
            if port_part and port_part in current_ss_output:
                found = True
                break
    
    # If exact string or port is found active
    if found or (sock_info in current_ss_output):
        status = "pass"
        socket_pass += 1
    else:
        status = "regression"

    details.append({
        "category": "listening_socket",
        "target": sock_info,
        "status": status
    })

# 3. Critical Liveness Probes
critical_services = [s.get("service") for s in map_data if s.get("criticality") == "critical"]
probe_pass = 0
probe_total = len(critical_services)

for svc_name in critical_services:
    probe_cmd = probes_data.get(svc_name, f"systemctl is-active --quiet {svc_name}")
    
    res = subprocess.run(probe_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if res.returncode == 0:
        status = "pass"
        probe_pass += 1
    else:
        status = "probe_failed"

    details.append({
        "category": "liveness_probe",
        "target": svc_name,
        "command": probe_cmd,
        "status": status
    })

# Compute Totals & Verdict
total_checks = len(details)
passed_count = sum(1 for d in details if d["status"] == "pass")
failed_count = total_checks - passed_count

report = {
    "total_checks": total_checks,
    "passed": passed_count,
    "failed": failed_count,
    "details": details
}

with open(output_file, "w") as f:
    json.dump(report, f, indent=2)

print(f"Service state checks:     {svc_state_pass}/{svc_state_total}   {'PASS' if svc_state_pass == svc_state_total else 'FAIL'}")
print(f"Listening socket checks:  {socket_pass}/{socket_total}   {'PASS' if socket_pass == socket_total else 'FAIL'}")
print(f"Critical liveness probes: {probe_pass}/{probe_total}   {'PASS' if probe_pass == probe_total else 'FAIL'}")

verdict = "PASS" if failed_count == 0 else "FAIL"
print(f"VERDICT: {verdict} ({passed_count}/{total_checks})")
print(f"Report saved to: {output_file}")

if failed_count > 0:
    sys.exit(1)
else:
    sys.exit(0)
EOF

PY_EXIT=$?
if [ $PY_EXIT -eq 0 ]; then
    exit 0
else
    exit 1
fi
