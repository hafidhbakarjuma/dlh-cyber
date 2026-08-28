#!/usr3/bin/env python3
import os
import sys
import json
import hashlib
import datetime
import re

# Determine evidence root from arguments or default
evidence_root = sys.argv[1] if len(sys.argv) > 1 else os.path.expanduser("~/evidence_pack_primary")
manifest_file = "source_inventory.json"

if not os.path.isdir(evidence_root):
    print(f"Error: Evidence root directory {evidence_root} does not exist.", file=sys.stderr)
    sys.exit(1)

print(f"Scanning evidence pack at: {evidence_root}")

sources = []
iso_regex = re.compile(r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b")

for root, dirs, files in os.walk(evidence_root):
    for file in files:
        full_path = os.path.join(root, file)
        if not os.path.isfile(full_path):
            continue
            
        rel_path = os.path.relpath(full_path, evidence_root)
        
        # Skip root-level files like README.txt or MANIFEST.sha256
        if "/" not in rel_path:
            continue

        size_bytes = os.path.getsize(full_path)
        
        # Calculate SHA256 hash
        sha256_hash = hashlib.sha256()
        with open(full_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        sha256 = sha256_hash.hexdigest()

        # Count lines/records
        line_count = 0
        try:
            with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                for _ in f:
                    line_count += 1
        except Exception:
            pass

        # Determine source type
        top_dir = rel_path.split("/")[0]
        if top_dir == "windows" or ("student_telemetry" in rel_path and file.endswith(".json")):
            source_type = "windows_json"
        elif top_dir == "linux":
            source_type = "linux_text"
        elif top_dir == "network":
            source_type = "network_csv" if file.endswith(".csv") else "network_json"
        else:
            source_type = "context_json"

        # Extract first and last timestamps
        first_ts, last_ts = None, None
        try:
            with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    if line.strip().startswith("{"):
                        try:
                            data = json.loads(line)
                            for k in ["@timestamp", "Timestamp", "time", "event_time", "datetime", "timestamp", "ot"]:
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
            pass

        entry = {
            "path": rel_path,
            "source_type": source_type,
            "size_bytes": size_bytes,
            "sha256": sha256,
            "parse_status": "ok"
        }

        if source_type == "linux_text":
            entry["line_count"] = line_count
        else:
            entry["record_count"] = line_count

        entry["first_event_time"] = first_ts if first_ts else "null"
        entry["last_event_time"] = last_ts if last_ts else "null"

        sources.append(entry)

# Sort sources by path for consistent ordering
sources.sort(key=lambda x: x["path"])

manifest = {
    "scanned_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "evidence_root": evidence_root,
    "sources": sources
}

with open(manifest_file, "w", encoding="utf-8") as f:
    json.dump(manifest, f, indent=2)

print(f"manifest written to {manifest_file}")
