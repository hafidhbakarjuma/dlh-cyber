#!/bin/bash
set -euo pipefail

PACK_ROOT="${1:-$HOME/evidence_pack_primary}"
OUT_FILE="linux_events.json"

python3 - "$PACK_ROOT" "$OUT_FILE" << 'PY'
import sys
import json
import re
from pathlib import Path

root = Path(sys.argv[1])
out_file = Path(sys.argv[2])

linux_dir = root / "linux"
telemetry_dir = root / "student_telemetry"

output_records = []

# Helper to extract key-value pairs or words from lines
def parse_kv_line(line):
    fields = {}
    # Simple regex for key=value or key="value with spaces"
    matches = re.findall(r'([a-zA-Z0-9_\-\.]+)=(?:"([^"]*)"|([^\s]+))', line)
    for k, v1, v2 in matches:
        fields[k] = v1 if v1 != '' else v2
    return fields

# 1. Parse auth.log
auth_file = linux_dir / "auth.log"
auth_count = 0
auth_re = re.compile(r'^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+([^\[:]+)(?:\[(\d+)\])?:?\s+(.*)$')

if auth_file.is_file():
    with auth_file.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            raw_msg = line.rstrip('\n')
            if not raw_msg.strip():
                continue
            auth_count += 1

            match = auth_re.match(raw_msg)
            timestamp_raw = match.group(1) if match else None
            hostname = match.group(2) if match else None
            program = match.group(3).strip() if match else None
            pid = match.group(4) if match and match.group(4) else None

            # Extract user if present in message
            user = None
            user_match = re.search(r'(?:user|for|by|from)\s+([a-zA-Z0-9_\-\.]+)', raw_msg)
            if user_match:
                user = user_match.group(1)

            parsed_fields = parse_kv_line(raw_msg)

            record = {
                "timestamp_raw": timestamp_raw,
                "hostname": hostname,
                "program": program,
                "pid": pid,
                "user": user,
                "raw_message": raw_msg,
                "parsed_fields": parsed_fields,
                "source_origin": "evidence_pack"
            }
            output_records.append(record)
print(f"parsing auth.log      ... {auth_count} lines  -> ~{auth_count} records")

# 2. Parse audit.log (Group multi-line audit records sharing the same timestamp/msg id)
audit_file = linux_dir / "audit.log"
audit_line_count = 0
audit_record_count = 0
audit_event_re = re.compile(r'type=([A-Z_]+).*audit\((\d+\.\d+):(\d+)\)')

if audit_file.is_file():
    current_group_id = None
    current_lines = []
    current_audit_type = None
    current_ts = None

    def flush_audit_group(g_id, lines, a_type, ts):
        if not lines:
            return
        raw_msg = " || ".join(lines)
        parsed_fields = {"audit_group_id": g_id}
        for l in lines:
            parsed_fields.update(parse_kv_line(l))

        # Extract user/uid if present
        user = parsed_fields.get("auid") or parsed_fields.get("uid") or parsed_fields.get("ses")

        record = {
            "timestamp_raw": ts,
            "hostname": "localhost",
            "audit_type": a_type or "UNKNOWN",
            "pid": parsed_fields.get("pid"),
            "user": user,
            "raw_message": raw_msg,
            "parsed_fields": parsed_fields,
            "source_origin": "evidence_pack"
        }
        output_records.append(record)

    with audit_file.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            raw_msg = line.rstrip('\n')
            if not raw_msg.strip():
                continue
            audit_line_count += 1

            match = audit_event_re.search(raw_msg)
            if match:
                a_type = match.group(1)
                ts = match.group(2)
                g_id = match.group(3)

                if current_group_id != g_id:
                    if current_lines:
                        flush_audit_group(current_group_id, current_lines, current_audit_type, current_ts)
                        audit_record_count += 1
                        current_lines = []
                    current_group_id = g_id
                    current_audit_type = a_type
                    current_ts = ts
                current_lines.append(raw_msg)
            else:
                current_lines.append(raw_msg)

    if current_lines:
        flush_audit_group(current_group_id, current_lines, current_audit_type, current_ts)
        audit_record_count += 1

print(f"parsing audit.log     ... {audit_line_count} lines  -> ~{audit_record_count} records (grouped)")

# 3. Parse syslog
syslog_file = linux_dir / "syslog"
syslog_count = 0
syslog_re = re.compile(r'^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+([^\[:]+)(?:\[(\d+)\])?:?\s+(.*)$')

if syslog_file.is_file():
    with syslog_file.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            raw_msg = line.rstrip('\n')
            if not raw_msg.strip():
                continue
            syslog_count += 1

            match = syslog_re.match(raw_msg)
            timestamp_raw = match.group(1) if match else None
            hostname = match.group(2) if match else None
            program = match.group(3).strip() if match else None
            pid = match.group(4) if match and match.group(4) else None

            user = None
            user_match = re.search(r'(?:user|for|by|from)\s+([a-zA-Z0-9_\-\.]+)', raw_msg)
            if user_match:
                user = user_match.group(1)

            parsed_fields = parse_kv_line(raw_msg)

            record = {
                "timestamp_raw": timestamp_raw,
                "hostname": hostname,
                "program": program,
                "pid": pid,
                "user": user,
                "raw_message": raw_msg,
                "parsed_fields": parsed_fields,
                "source_origin": "evidence_pack"
            }
            output_records.append(record)
print(f"parsing syslog        ... {syslog_count} lines  -> ~{syslog_count} records")

# 4. Append student telemetry linux events
tel_file = telemetry_dir / "linux_events.json"
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
                if not record.get("source_origin"):
                    record["source_origin"] = "student_telemetry"
                output_records.append(record)
                tel_count += 1
            except json.JSONDecodeError:
                continue
print(f"appending student telemetry ... {tel_count} records")

# Write output as NDJSON
with out_file.open("w", encoding="utf-8") as f:
    for record in output_records:
        f.write(json.dumps(record) + "\n")

print(f"linux_events.json: {len(output_records)} records")
PY

