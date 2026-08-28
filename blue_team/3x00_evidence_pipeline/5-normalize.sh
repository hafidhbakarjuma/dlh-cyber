#!/bin/bash
set -euo pipefail

OUT_NORMALIZED="normalized_events.json"
OUT_QUARANTINE="quarantine.json"

python3 - "$OUT_NORMALIZED" "$OUT_QUARANTINE" << 'PY'
import sys
import json
import re
from datetime import datetime, timezone
from pathlib import Path

norm_out_path = Path(sys.argv[1])
quar_out_path = Path(sys.argv[2])

# Load schema to know required fields dynamically
schema_path = Path("event_schema.json")
required_fields = ["timestamp", "hostname", "source_type", "event_category", "severity", "raw_message"]
if schema_path.is_file():
    try:
        with schema_path.open("r", encoding="utf-8") as f:
            schema_data = json.load(f)
            required_fields = [field["name"] for field in schema_data.get("fields", []) if field.get("required")]
    except Exception:
        pass

all_schema_fields = [
    "timestamp", "hostname", "source_type", "event_category", 
    "severity", "user", "process_name", "src_ip", "dst_ip", "raw_message"
]

def normalize_time(value):
    if value is None:
        return None
    value = str(value).strip()
    if not value:
        return None

    # Unix epoch
    if re.fullmatch(r"\d+(?:\.\d+)?", value):
        try:
            return datetime.fromtimestamp(float(value), timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        except (ValueError, OverflowError):
            return None

    # ISO 8601
    try:
        iso = re.sub(r"([+-]\d{2})(\d{2})$", r"\1:\2", value.replace("Z", "+00:00"))
        dt = datetime.fromisoformat(iso)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        pass

    # PCAP / standard log format
    try:
        dt = datetime.strptime(value, "%m/%d/%Y %I:%M:%S %p")
        dt = dt.replace(tzinfo=timezone.utc)
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        return None

def map_severity(record):
    raw = str(record.get("raw_message", "")).lower()
    event_id = str(record.get("event_id", ""))
    if "fail" in raw or "error" in raw or event_id in ["4625", "1102"]:
        return "medium"
    if "crit" in raw or "emergency" in raw:
        return "critical"
    return "info"

def map_category(record):
    channel = str(record.get("channel", "")).lower()
    prog = str(record.get("program", "")).lower()
    audit_type = str(record.get("audit_type", "")).lower()
    if "security" in channel or "auth" in prog or "pam" in prog or audit_type:
        return "authentication"
    if "sysmon" in channel or "process" in prog:
        return "process"
    if "powershell" in channel:
        return "execution"
    return "system"

stats = {
    "windows_json": {"normalized": 0, "quarantined": 0},
    "linux_text": {"normalized": 0, "quarantined": 0}
}

normalized_records = []
quarantined_records = []

def process_input_file(filepath, default_source_type):
    if not filepath.is_file():
        return

    with filepath.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                raw_rec = json.loads(line)
                if not isinstance(raw_rec, dict):
                    continue

                src_type = raw_rec.get("source_origin") or default_source_type

                # Robust timestamp extraction (checks timestamp_raw, timestamp, or event_time)
                ts_candidate = raw_rec.get("timestamp_raw") or raw_rec.get("timestamp") or raw_rec.get("event_time")
                timestamp = normalize_time(ts_candidate)

                hostname = raw_rec.get("hostname") or ("unknown-win-host" if "windows" in default_source_type else "localhost")
                raw_msg = raw_rec.get("raw_message") or ""

                event_category = map_category(raw_rec)
                severity = map_severity(raw_rec)

                event_data = raw_rec.get("event_data", {})
                if not isinstance(event_data, dict):
                    event_data = {}

                user = raw_rec.get("user") or event_data.get("TargetUserName") or event_data.get("SubjectUserName")
                process_name = raw_rec.get("program") or event_data.get("Image")

                src_ip = raw_rec.get("src_ip") or event_data.get("SourceIp") or event_data.get("IpAddress")
                dst_ip = raw_rec.get("dst_ip") or event_data.get("DestinationIp")

                norm_rec = {
                    "timestamp": timestamp,
                    "hostname": hostname,
                    "source_type": src_type,
                    "event_category": event_category,
                    "severity": severity,
                    "user": user,
                    "process_name": process_name,
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "raw_message": raw_msg
                }

                # Ensure all schema keys are explicitly present
                for field in all_schema_fields:
                    if field not in norm_rec:
                        norm_rec[field] = None

                # Validate required fields *after* initialization
                missing_req = [f for f in required_fields if norm_rec.get(f) is None]

                category_key = "windows_json" if "windows" in default_source_type else "linux_text"

                if missing_req:
                    raw_rec["quarantine_reason"] = f"Missing required fields: {missing_req}"
                    quarantined_records.append(raw_rec)
                    stats[category_key]["quarantined"] += 1
                elif not timestamp:
                    raw_rec["quarantine_reason"] = f"Unparseable or missing timestamp: {ts_candidate}"
                    quarantined_records.append(raw_rec)
                    stats[category_key]["quarantined"] += 1
                else:
                    normalized_records.append(norm_rec)
                    stats[category_key]["normalized"] += 1

            except json.JSONDecodeError:
                continue

process_input_file(Path("windows_events.json"), "windows_json")
process_input_file(Path("linux_events.json"), "linux_text")

with norm_out_path.open("w", encoding="utf-8") as f:
    for rec in normalized_records:
        f.write(json.dumps(rec) + "\n")

with quar_out_path.open("w", encoding="utf-8") as f:
    for rec in quarantined_records:
        f.write(json.dumps(rec) + "\n")

tot_norm = stats["windows_json"]["normalized"] + stats["linux_text"]["normalized"]
tot_quar = stats["windows_json"]["quarantined"] + stats["linux_text"]["quarantined"]

print(f"windows_json     : normalized {stats['windows_json']['normalized']:5} quarantined {stats['windows_json']['quarantined']}")
print(f"linux_text       : normalized {stats['linux_text']['normalized']:5} quarantined {stats['linux_text']['quarantined']}")
print(f"total            : normalized {tot_norm:5} quarantined {tot_quar}")
print("normalized_events.json written")
print("quarantine.json  written")
PY
