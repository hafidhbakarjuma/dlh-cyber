#!/bin/bash
set -euo pipefail

EVIDENCE_ROOT="${1:-$HOME/evidence_pack_primary}"
MANIFEST_FILE="source_inventory.json"

if [ ! -d "$EVIDENCE_ROOT" ]; then
    echo "Error: Evidence root directory $EVIDENCE_ROOT does not exist." >&2
    exit 1
fi

echo "Scanning evidence pack at: $EVIDENCE_ROOT"

python3 - "$EVIDENCE_ROOT" "$MANIFEST_FILE" << 'PY_SCRIPT'
import os
import sys
import json
import hashlib
import datetime
import re

evidence_root = sys.argv[1]
manifest_file = sys.argv[2]

sources = []
iso_regex = re.compile(r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b")

for root, dirs, files in os.walk(evidence_root):
    for file in files:
        full_path = os.path.join(root, file)
        if not os.path.isfile(full_path):
            continue
            
        rel_path = os.path.relpath(full_path, evidence_root)
        
        # Skip technical manifest/hash files if present, but include other files
        if file in ["MANIFEST.sha256", "source_inventory.json"]:
            continue

        size_bytes = os.path.getsize(full_path)
        
        sha256_hash = hashlib.sha256()
        try:
            with open(full_path, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            sha256 = sha256_hash.hexdigest()
        except Exception:
            sha256 = ""

        line_count = 0
        record_count = 0
        parse_status = "ok"
        
        try:
            with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line_count += 1
                    stripped = line.strip()
                    if stripped.startswith("{") or "," in stripped:
                        record_count += 1
            if record_count == 0:
                record_count = line_count
        except Exception:
            parse_status = "error"

        # Determine source type based on path or extension
        if "linux" in rel_path:
            source_type = "linux_text"
        elif "windows" in rel_path or "student_telemetry" in rel_path:
            source_type = "windows_json"
        elif "network" in rel_path:
            source_type = "network_csv" if file.endswith(".csv") else "network_json"
        elif "context" in rel_path:
            source_type = "context_json"
        else:
            if file.endswith(".json"):
                source_type = "windows_json"
            elif file.endswith(".csv"):
                source_type = "network_csv"
            else:
                source_type = "linux_text"

        first_ts, last_ts = None, None
        try:
            with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    if line.strip().startswith("{"):
                        try:
                            data = json.loads(line)
                            for k in ["@timestamp", "Timestamp", "time", "event_time", "datetime", "timestamp"]:
                                if k in data and isinstance(data[k], str):
                                    if not first_ts: 
                                        first_ts = data[k]
                                    last_ts = data[k]
                                    break
                        except Exception:
                            pass
                    matches = iso_regex.findall(line)
                    if matches:
                        if not first_ts: 
                            first_ts = matches[0]
                        last_ts = matches[-1]
        except Exception:
            parse_status = "partial"

        entry = {
            "path": rel_path,
            "source_type": source_type,
            "size_bytes": size_bytes,
            "sha256": sha256
        }

        if source_type == "linux_text":
            entry["line_count"] = line_count
        else:
            entry["record_count"] = record_count if record_count > 0 else line_count

        entry["first_event_time"] = first_ts if first_ts else None
        entry["last_event_time"] = last_ts if last_ts else None
        entry["parse_status"] = parse_status

        sources.append(entry)

sources.sort(key=lambda x: x["path"])

manifest = {
    "scanned_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "evidence_root": evidence_root,
    "sources": sources
}

with open(manifest_file, "w", encoding="utf-8") as f:
    json.dump(manifest, f, indent=2)

print(f"manifest written to {manifest_file}")
PY_SCRIPT
