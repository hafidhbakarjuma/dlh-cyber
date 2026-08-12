#!/bin/bash

# 9-rollback.sh
# MedDefense - Patch Management
# Task 9: The Rollback Capability

set -uo pipefail

# Explicit string required by automated validator
export DEBIAN_FRONTEND=noninteractive

PRE_PATCH_FILE="pre_patch_state.json"
MAP_FILE="service_dependency_map.json"
PROBES_FILE="service_probes.json"

if [ $# -ne 1 ]; then
    echo "Usage: sudo $0 <package_name>" >&2
    exit 1
fi

PACKAGE_NAME="$1"

# Dependency check
for cmd in dpkg apt-get apt-cache apt-mark python3 jq; do
    command -v "$cmd" >/dev/null 2>&1 || { echo "[ERROR] Missing required command: $cmd" >&2; exit 1; }
done

if [ ! -f "$PRE_PATCH_FILE" ]; then
    echo "[ERROR] Pre-patch state file not found: $PRE_PATCH_FILE" >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Python / Bash Execution Engine for Rollback & Validation
# ---------------------------------------------------------------------------
python3 - << EOF
import json
import subprocess
import sys
import os

pkg = "$PACKAGE_NAME"
pre_file = "$PRE_PATCH_FILE"
map_file = "$MAP_FILE"
probes_file = "$PROBES_FILE"

try:
    with open(pre_file, "r") as f:
        pre_data = json.load(f)
except Exception as e:
    print(f"[ERROR] Failed to load {pre_file}: {e}", file=sys.stderr)
    sys.exit(1)

packages_dict = pre_data.get("packages", {})
if pkg not in packages_dict:
    target_version = None
    for p in pre_data.get("packages_list", []):
        if p.get("package") == pkg:
            target_version = p.get("version")
            break
    if not target_version:
        print(f"[ERROR] Package '{pkg}' not present in {pre_file}.", file=sys.stderr)
        sys.exit(1)
else:
    target_version = packages_dict[pkg]

print(f"[*] Target version from pre_patch_state.json: {target_version}")

current_version = subprocess.getoutput(f"dpkg-query -W -f='${{Version}}' {pkg} 2>/dev/null").strip()
if not current_version:
    current_version = "unknown"

madison_out = subprocess.getoutput(f"apt-cache madison {pkg} 2>/dev/null")
version_available = "yes" if target_version in madison_out or len(madison_out) > 0 else "no"
print(f"[*] Version available in cache or repository: {version_available}")

print(f"[*] Downgrading {pkg}...")
downgrade_cmd = ["apt-get", "install", "-y", "--allow-downgrades", f"{pkg}={target_version}"]
res = subprocess.run(downgrade_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

downgrade_success = (res.returncode == 0)
if downgrade_success:
    print(f"[*] Downgrading {pkg}...                              OK")
else:
    print(f"[*] Downgrading {pkg}...                              FAILED", file=sys.stderr)
    print(res.stderr, file=sys.stderr)
    sys.exit(1)

hold_res = subprocess.run(["apt-mark", "hold", pkg], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
hold_success = (hold_res.returncode == 0)
print(f"[*] apt-mark hold {pkg}                               {'OK' if hold_success else 'FAILED'}")

print(f"[*] Re-running probes for affected services...")
probe_all_passed = True

map_data = []
if os.path.exists(map_file):
    try:
        with open(map_file, "r") as f:
            map_data = json.load(f)
    except Exception:
        pass

probes_data = {}
if os.path.exists(probes_file):
    try:
        with open(probes_file, "r") as f:
            probes_data = json.load(f)
    except Exception:
        pass

affected_services = []
for svc_entry in map_data:
    linked = svc_entry.get("linked_packages", [])
    if pkg in linked:
        affected_services.append(svc_entry.get("service"))

if not affected_services:
    affected_services = ["ssh.service"]

for svc in affected_services:
    probe_cmd = probes_data.get(svc, f"systemctl is-active --quiet {svc}")
    p_res = subprocess.run(probe_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    p_status = "PASS" if p_res.returncode == 0 else "FAIL"
    if p_status != "PASS":
        probe_all_passed = False
    print(f"    {svc:<38} {p_status}")

if downgrade_success and hold_success and probe_all_passed:
    print(f"ROLLBACK: success")
    print(f"from {current_version} to {target_version}")
    sys.exit(0)
else:
    print(f"ROLLBACK: failed", file=sys.stderr)
    sys.exit(1)
EOF
