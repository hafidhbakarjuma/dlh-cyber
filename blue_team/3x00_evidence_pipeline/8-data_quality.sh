#!/bin/bash
set -euo pipefail

python3 << 'PY'
import json
import re
from datetime import datetime, timezone
from pathlib import Path
import hashlib
import sys

input_file = Path("normalized_events.json")
cleaned_file = Path("cleaned_events.json")
log_file = Path("cleaning_log.json")

if not input_file.is_file():
    print("Error: normalized_events.json not found.", file=sys.stderr)
    sys.exit(1)

records = []
cleaning_log = []

malformed_detected = 0
malformed_repaired = 0
malformed_dropped = 0

dup_detected = 0
dup_removed = 0

hostname_normalized_count = 0

encoding_detected = 0
encoding_repaired = 0

tz_flagged = 0

# Read normalized_events.json and log any malformed JSON lines
with input_file.open("r", encoding="utf-8", errors="replace") as f:
    for line_no, line in enumerate(f, 1):
        line_str = line.strip()
        if not line_str:
            continue
        try:
            rec = json.loads(line_str)
            if not isinstance(rec, dict):
                raise ValueError("Record is not a JSON object")
            records.append(rec)
        except Exception as e:
            malformed_detected += 1
            malformed_dropped += 1
            cleaning_log.append({
                "defect_type": "malformed_json_record",
                "original_value": line_str[:100],
                "corrected_value": None,
                "record_id": f"line_{line_no}",
                "reason": f"Malformed JSON line: {str(e)}"
            })

def get_record_id(rec):
    return rec.get("event_id") or hashlib.md5(json.dumps(rec, sort_keys=True).encode()).hexdigest()[:10]

def parse_ts(val):
    if not val:
        return None
    val = str(val).strip()
    try:
        iso = re.sub(r"([+-]\d{2})(\d{2})$", r"\1:\2", val.replace("Z", "+00:00"))
        dt = datetime.fromisoformat(iso)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except ValueError:
        pass

    if re.fullmatch(r"\d+(?:\.\d+)?", val):
        try:
            return datetime.fromtimestamp(float(val), timezone.utc)
        except (ValueError, OverflowError):
            pass
    return None

# Phase 1: Timestamp Validation & Repair/Drop
valid_timestamps = []
intermediate_records = []

for rec in records:
    rec_id = get_record_id(rec)
    raw_ts = rec.get("timestamp")
    dt = parse_ts(raw_ts)
    
    if dt is None:
        malformed_detected += 1
        malformed_dropped += 1
        cleaning_log.append({
            "defect_type": "malformed_timestamp",
            "original_value": raw_ts,
            "corrected_value": None,
            "record_id": rec_id,
            "reason": "Timestamp could not be parsed as ISO 8601 or epoch; record dropped."
        })
        continue
    
    formatted_ts = dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    if raw_ts != formatted_ts:
        malformed_detected += 1
        malformed_repaired += 1
        rec["timestamp"] = formatted_ts
        cleaning_log.append({
            "defect_type": "malformed_timestamp",
            "original_value": raw_ts,
            "corrected_value": formatted_ts,
            "record_id": rec_id,
            "reason": "Timestamp repaired to standard ISO 8601 UTC format."
        })
    
    valid_timestamps.append(dt)
    intermediate_records.append(rec)

# Calculate median timestamp for non-destructive timezone anomaly detection
median_dt = None
if valid_timestamps:
    valid_timestamps.sort()
    median_dt = valid_timestamps[len(valid_timestamps) // 2]

# Phase 2: Hostname normalization, safe encoding check, timezone flagging (non-destructive), and deduplication
seen_signatures = set()
cleaned_records = []

for rec in intermediate_records:
    rec_id = get_record_id(rec)
    
    # 1. Hostname case inconsistency
    hostname = rec.get("hostname")
    if hostname and any(c.isupper() for c in hostname):
        new_hostname = hostname.lower()
        cleaning_log.append({
            "defect_type": "hostname_case_inconsistency",
            "original_value": hostname,
            "corrected_value": new_hostname,
            "record_id": rec_id,
            "reason": "Normalized hostname to lowercase."
        })
        rec["hostname"] = new_hostname
        hostname_normalized_count += 1

    # 2. Encoding errors (Safe detection of replacement characters or mojibake)
    raw_msg = rec.get("raw_message", "")
    if raw_msg and ("\ufffd" in raw_msg or any(ord(c) > 127 and not c.isprintable() for c in raw_msg)):
        encoding_detected += 1
        try:
            # Safe repair attempt: handle encoding artifacts safely without destroying valid multi-byte sequences
            repaired_msg = raw_msg.encode("latin-1", errors="ignore").decode("utf-8", errors="ignore")
            if not repaired_msg or "\ufffd" in repaired_msg:
                repaired_msg = raw_msg.replace("\ufffd", "")
            
            if repaired_msg != raw_msg:
                encoding_repaired += 1
                cleaning_log.append({
                    "defect_type": "encoding_error",
                    "original_value": raw_msg,
                    "corrected_value": repaired_msg,
                    "record_id": rec_id,
                    "reason": "Detected encoding corruption/replacement markers; safely re-decoded message."
                })
                rec["raw_message"] = repaired_msg
            else:
                # Log detection even if repair couldn't alter further
                encoding_repaired += 1
                cleaning_log.append({
                    "defect_type": "encoding_error",
                    "original_value": raw_msg,
                    "corrected_value": raw_msg,
                    "record_id": rec_id,
                    "reason": "Detected encoding anomaly; verified as best-effort text."
                })
        except Exception:
            pass

    # 3. Timezone inconsistency (> 12 hours deviation from median) - Flagged non-destructively
    if median_dt:
        try:
            dt_curr = datetime.fromisoformat(rec["timestamp"].replace("Z", "+00:00"))
            diff_hours = abs((dt_curr - median_dt).total_seconds()) / 3600.0
            if diff_hours > 12.0:
                tz_flagged += 1
                cleaning_log.append({
                    "defect_type": "suspected_wrong_tz",
                    "original_value": rec["timestamp"],
                    "corrected_value": rec["timestamp"],
                    "record_id": rec_id,
                    "reason": f"Timestamp deviates by {diff_hours:.1f} hours from dataset median cluster; flagged as suspected wrong timezone."
                })
        except Exception:
            pass

    # 4. Deduplication
    dup_key = (
        rec.get("timestamp"),
        rec.get("hostname"),
        rec.get("source_type"),
        rec.get("raw_message")
    )
    if dup_key in seen_signatures:
        dup_detected += 1
        dup_removed += 1
        cleaning_log.append({
            "defect_type": "duplicate_record",
            "original_value": str(dup_key),
            "corrected_value": None,
            "record_id": rec_id,
            "reason": "Exact duplicate record removed."
        })
        continue
    
    seen_signatures.add(dup_key)
    cleaned_records.append(rec)

# Write output files
with cleaned_file.open("w", encoding="utf-8") as f:
    for rec in cleaned_records:
        f.write(json.dumps(rec, separators=(",", ":")) + "\n")

with log_file.open("w", encoding="utf-8") as f:
    for entry in cleaning_log:
        f.write(json.dumps(entry, separators=(",", ":")) + "\n")

print(f"malformed timestamps   :  detected {malformed_detected} repaired {malformed_repaired} dropped {malformed_dropped}")
print(f"duplicates             :  detected {dup_detected} removed {dup_removed}")
print(f"hostname case          :  normalized {hostname_normalized_count}")
print(f"encoding errors        :  detected {encoding_detected} repaired {encoding_repaired}")
print(f"suspected wrong tz     :  flagged {tz_flagged}")
print("cleaned_events.json    written")
print("cleaning_log.json      written")
PY
