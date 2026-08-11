#!/bin/bash

# 6-config_drift.sh
# MedDefense - Patch Management
# Task 6: The Configuration Drift Detector

set -uo pipefail

PRE_PATCH_FILE="pre_patch_state.json"
LOG_FILE="patch_execution_log.json"
OUTPUT_FILE="config_drift.json"

# Dependency checks
for cmd in jq python3 sha256sum dpkg-query diff; do
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
import difflib

pre_file = "pre_patch_state.json"
log_file = "patch_execution_log.json"
output_file = "config_drift.json"

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

# Also collect current package-tracked conffiles under /etc via dpkg-query to catch new ones
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

    # Determine classification
    if not file_exists:
        classification = "missing"
        counts["missing"] += 1
        continue  # skip hash calculation if missing

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
        continue # skip unchanged files from detailed array if desired, or keep summary
    else:
        classification = "modified"
        counts["modified"] += 1

    # Find owning package via dpkg -S
    owning_pkg = subprocess.getoutput(f"dpkg-S {path} 2>/dev/null | head -n1 | cut -d: -f1").strip()
    if not owning_pkg or "no path found" in owning_pkg:
        owning_pkg = "unknown"

    # Determine if drift is expected (owning package was upgraded in patch run)
    is_expected = True if owning_pkg in upgraded_packages else False
    if classification == "modified" and not is_expected:
        unexpected_drift_found = True

    # Generate truncated unified diff if modified (comparing backup/baseline if available or noting change)
    diff_snippet = ""
    if classification == "modified":
        # Since we don't store full pre-patch content in JSON by default, we capture basic diff metadata or file attribute diff
        diff_snippet = f"File hash changed from {pre_hash[:12]}... to {current_hash[:12]}..."

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
