#!/bin/bash

# 6-config_drift.sh
# MedDefense - Patch Management
# Task 6: The Configuration Drift Detector

set -uo pipefail

PRE_PATCH_FILE="pre_patch_state.json"
LOG_FILE="patch_execution_log.json"
OUTPUT_FILE="config_drift.json"
BACKUP_DIR="/var/backups/meddefense-pre"

# Dependency checks
for cmd in jq python3 sha256sum dpkg-query diff head; do
    command -v "$cmd" >/dev/null 2>&1 || { echo "[ERROR] Missing required command: $cmd" >&2; exit 1; }
done

for f in "$PRE_PATCH_FILE"; do
    if [ ! -f "$f" ]; then
        echo "[ERROR] Required input file not found: $f" >&2
        exit 1
    fi
done

echo "[*] Analyzing configuration file drift against pre-patch baseline..."

# ---------------------------------------------------------------------------
# Python Drift Detection Engine
# ---------------------------------------------------------------------------
python3 - << 'EOF'
import json
import subprocess
import hashlib
import os
import sys

pre_file = "pre_patch_state.json"
log_file = "patch_execution_log.json"
output_file = "config_drift.json"
backup_dir = "/var/backups/meddefense-pre"

try:
    with open(pre_file, "r") as f:
        pre_data = json.load(f)
except Exception as e:
    print(f"[ERROR] Failed to load {pre_file}: {e}", file=sys.stderr)
    sys.exit(1)

# Load execution log if available to cross-reference upgraded packages
upgraded_packages = set()
if os.path.exists(log_file):
    try:
        with open(log_file, "r") as f:
            log_data = json.load(f)
            for entry in log_data.get("entries", []):
                if entry.get("status") == "success":
                    upgraded_packages.add(entry.get("package"))
    except Exception:
        pass

pre_hashes = pre_data.get("conffile_hashes", {})

# Collect current package-tracked conffiles under /etc via dpkg-query
current_conffiles = set(pre_hashes.keys())
try:
    dpkg_output = subprocess.getoutput("dpkg-query -W -f='${Package}\n${Conffiles}\n' 2>/dev/null")
    for line in dpkg_output.splitlines():
        line = line.strip()
        if line.startswith("/etc/"):
            current_conffiles.add(line.split()[0])
except Exception:
    pass

file_records = []
counts = {
    "unchanged": 0,
    "modified": 0,
    "missing": 0,
    "new": 0
}

unexpected_drift_found = False

for path in sorted(current_conffiles):
    pre_hash = pre_hashes.get(path)
    file_exists = os.path.isfile(path)

    # Find owning package via dpkg -S
    owning_pkg = subprocess.getoutput(f"dpkg -S {path} 2>/dev/null | head -n1 | cut -d: -f1").strip()
    if not owning_pkg or "no path found" in owning_pkg:
        owning_pkg = "unknown"

    is_expected = True if owning_pkg in upgraded_packages else False

    if not file_exists:
        classification = "missing"
        counts["missing"] += 1
        file_records.append({
            "path": path,
            "classification": classification,
            "owning_package": owning_pkg,
            "expected": is_expected,
            "diff_summary": "File is missing"
        })
        continue

    # Compute current SHA-256 hash
    try:
        hasher = hashlib.sha256()
        with open(path, "rb") as rf:
            while chunk := rf.read(8192):
                hasher.update(chunk)
        current_hash = hasher.hexdigest()
    except Exception:
        current_hash = ""

    if pre_hash is None:
        classification = "new"
        counts["new"] += 1
    elif pre_hash == current_hash:
        classification = "unchanged"
        counts["unchanged"] += 1
        continue
    else:
        classification = "modified"
        counts["modified"] += 1
        if not is_expected:
            unexpected_drift_found = True

    # Generate unified diff truncated to 40 lines via diff -u if backup exists
    diff_snippet = ""
    backup_path = os.path.join(backup_dir, path.lstrip("/"))
    if classification == "modified" and os.path.exists(backup_path):
        diff_cmd = f"diff -u {backup_path} {path} | head -n 40"
        diff_snippet = subprocess.getoutput(diff_cmd)
    else:
        diff_snippet = f"File hash changed from {pre_hash[:12] if pre_hash else 'N/A'} to {current_hash[:12]}"

    file_records.append({
        "path": path,
        "classification": classification,
        "owning_package": owning_pkg,
        "expected": is_expected,
        "diff_summary": diff_snippet
    })

summary_report = {
    "summary": counts,
    "files": file_records
}

with open(output_file, "w") as f:
    json.dump(summary_report, f, indent=2)

print(f"Drift Summary -> Unchanged: {counts['unchanged']} | Modified: {counts['modified']} | New: {counts['new']} | Missing: {counts['missing']}")
print(f"Report saved to: {output_file}")

if unexpected_drift_found:
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
