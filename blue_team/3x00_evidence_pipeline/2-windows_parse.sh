#!/bin/bash
set -euo pipefail

PACK_ROOT="${1:-$HOME/evidence_pack_primary}"
OUT_FILE="windows_events.json"

python3 - "$PACK_ROOT" "$OUT_FILE" << 'PY'
import sys
import json
from pathlib import Path

root = Path(sys.argv[1])
out_file = Path(sys.argv[2])

windows_dir = root / "windows"
telemetry_dir = root / "student_telemetry"

required_keys = [
    "timestamp_raw", "hostname", "event_id", "channel", 
    "provider", "raw_message", "event_data", "source_origin"
]

total_records = 0
output_records = []

def process_file(file_path, default_origin):
    global total_records
    count = 0
    if not file_path.is_file():
        print(f"reading {file_path.name:20} ... 0 records")
        return count

    with file_path.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
                if not isinstance(record, dict):
                    continue

                # Ensure all required keys exist
                for key in required_keys:
                    if key not in record:
                        record[key] = None

                # Set or preserve source_origin
                if not record.get("source_origin"):
                    record["source_origin"] = default_origin

                output_records.append(record)
                count += 1
            except json.JSONDecodeError:
                continue

    print(f"reading {file_path.name:20} ... {count} records")
    return count

# 1. Read primary Windows JSON files
sec_count = process_file(windows_dir / "security.json", "evidence_pack")
sys_count = process_file(windows_dir / "sysmon.json", "evidence_pack")
ps_count  = process_file(windows_dir / "powershell.json", "evidence_pack")

# 2. Read student telemetry windows events
tel_file = telemetry_dir / "windows_events.json"
tel_count = 0
if tel_file.is_file():
    with tel_file.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
                if not isinstance(record, dict):
                    continue
                for key in required_keys:
                    if key not in record:
                        record[key] = None
                if not record.get("source_origin"):
                    record["source_origin"] = "student_telemetry"
                output_records.append(record)
                tel_count += 1
            except json.JSONDecodeError:
                continue
print(f"appending student telemetry ... {tel_count} records")

# Write combined output as newline-delimited JSON (NDJSON)
with out_file.open("w", encoding="utf-8") as f:
    for record in output_records:
        f.write(json.dumps(record) + "\n")

total_records = len(output_records)
print(f"windows_events.json: {total_records} records")
PY
