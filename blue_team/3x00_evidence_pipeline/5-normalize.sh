#!/bin/bash
set -euo pipefail

python3 << 'PY'
import json
import re
from datetime import datetime, timezone
from pathlib import Path

normal = []
quarantine = []

def get_timestamp(value):
    if not value:
        return None

    text = str(value).strip()

    try:
        dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    except ValueError:
        pass

    match = re.match(r"^(\d+(?:\.\d+)?)$", text)
    if match:
        try:
            dt = datetime.fromtimestamp(float(match.group(1)), timezone.utc)
            return dt.isoformat().replace("+00:00", "Z")
        except (ValueError, OverflowError):
            pass

    match = re.match(r"^(\d+(?:\.\d+)?):", text)
    if match:
        try:
            dt = datetime.fromtimestamp(float(match.group(1)), timezone.utc)
            return dt.isoformat().replace("+00:00", "Z")
        except (ValueError, OverflowError):
            pass

    match = re.match(
        r"^([A-Z][a-z]{2})\s+(\d{1,2})\s+"
        r"(\d{2}):(\d{2}):(\d{2})$",
        text
    )
    if match:
        try:
            year = datetime.now(timezone.utc).year
            dt = datetime.strptime(
                f"{year} {match.group(1)} {int(match.group(2)):02d} "
                f"{match.group(3)}:{match.group(4)}:{match.group(5)}",
                "%Y %b %d %H:%M:%S"
            ).replace(tzinfo=timezone.utc)
            return dt.isoformat().replace("+00:00", "Z")
        except ValueError:
            pass

    return None

def process(filename, source):
    good = 0
    bad = 0
    path = Path(filename)
    
    if not path.is_file():
        print(f"{source:<17}: normalized 0 quarantined 0")
        return good, bad

    with path.open("r", encoding="utf-8", errors="replace") as f:
        for line_no, line in enumerate(f, 1):
            line_str = line.strip()
            if not line_str:
                continue
            
            r = None
            try:
                r = json.loads(line_str)

                if not isinstance(r, dict):
                    raise ValueError("record is not an object")

                ts = get_timestamp(r.get("timestamp_raw") or r.get("timestamp"))

                if not ts:
                    raise ValueError("unparseable timestamp")

                hostname = r.get("hostname")
                if not hostname:
                    hostname = "unknown"

                raw = r.get("raw_message")
                if raw is None:
                    raise ValueError("missing required raw_message")

                parsed = r.get("parsed_fields", {})
                event_data = r.get("event_data", {})

                if not isinstance(parsed, dict):
                    parsed = {}

                if not isinstance(event_data, dict):
                    event_data = {}

                if source == "windows_json":
                    category = r.get("channel") or "unknown"
                    user = r.get("user") or event_data.get("SubjectUserName") or event_data.get("TargetUserName")
                    process_name = r.get("process_name") or event_data.get("Image")
                    provider = r.get("provider")
                    data = event_data
                else:
                    category = r.get("audit_type") or r.get("program") or "unknown"
                    user = r.get("user") or parsed.get("user") or parsed.get("acct")
                    process_name = r.get("program")
                    provider = r.get("program") or r.get("audit_type")
                    data = parsed

                event_id = r.get("event_id")

                normal.append({
                    "timestamp": ts,
                    "hostname": hostname,
                    "source_type": source,
                    "event_category": category,
                    "severity": r.get("severity"),
                    "user": user,
                    "process_name": process_name,
                    "process_id": r.get("process_id", r.get("pid")),
                    "src_ip": r.get("src_ip"),
                    "src_port": r.get("src_port"),
                    "dst_ip": r.get("dst_ip"),
                    "dst_port": r.get("dst_port"),
                    "protocol": r.get("protocol"),
                    "event_id": str(event_id) if event_id is not None else None,
                    "provider": provider,
                    "raw_message": raw,
                    "event_data": data,
                    "source_origin": r.get("source_origin", "evidence_pack")
                })
                good += 1

            except Exception as e:
                quarantine.append({
                    "quarantine_reason": str(e),
                    "source_file": filename,
                    "source_line": line_no,
                    "original_record": r if r is not None else line_str
                })
                bad += 1

    print(f"{source:<17}: normalized {good} quarantined {bad}")
    return good, bad

w_good, w_bad = process("windows_events.json", "windows_json")
l_good, l_bad = process("linux_events.json", "linux_text")

tot_norm = w_good + l_good
tot_quar = w_bad + l_bad

with open("normalized_events.json", "w", encoding="utf-8") as f:
    for record in normal:
        f.write(json.dumps(record, separators=(",", ":")) + "\n")

with open("quarantine.json", "w", encoding="utf-8") as f:
    for record in quarantine:
        f.write(json.dumps(record, separators=(",", ":")) + "\n")

print(f"total            : normalized {tot_norm} quarantined {tot_quar}")
print("normalized_events.json written")
print("quarantine.json  written")
PY
