#!/bin/bash
set -euo pipefail

# Determine base evidence pack path from argument or default safely
EVIDENCE_DIR="${1:-/home/student/evidence_pack_primary}"
NET_DIR="${EVIDENCE_DIR}/network"

echo "Looking for network logs in: $NET_DIR"

python3 - "$NET_DIR" << 'PY'
import sys
import json
import csv
import re
from datetime import datetime, timezone
from pathlib import Path

net_dir = Path(sys.argv[1])
norm_file = Path("normalized_events.json")
network_only_file = Path("network_events.json")

all_network_records = []

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

    # Standard log formats (e.g., PCAP summary: MM/DD/YYYY HH:MM:SS AM/PM)
    try:
        dt = datetime.strptime(value, "%m/%d/%Y %I:%M:%S %p")
        dt = dt.replace(tzinfo=timezone.utc)
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        return None

# 1. Process firewall.csv
fw_count = 0
fw_path = net_dir / "firewall.csv"
if fw_path.is_file():
    with fw_path.open("r", encoding="utf-8", errors="replace") as f:
        reader = csv.DictReader(f)
        for row in reader:
            ts = normalize_time(row.get("timestamp"))
            record = {
                "timestamp": ts,
                "hostname": "firewall-gateway",
                "source_type": "firewall",
                "event_category": "network",
                "severity": "info" if row.get("action") == "ALLOW" else "medium",
                "user": None,
                "process_name": None,
                "process_id": None,
                "src_ip": row.get("src_ip"),
                "src_port": int(row["src_port"]) if row.get("src_port") and row["src_port"].isdigit() else None,
                "dst_ip": row.get("dst_ip"),
                "dst_port": int(row["dst_port"]) if row.get("dst_port") and row["dst_port"].isdigit() else None,
                "protocol": row.get("protocol"),
                "event_id": None,
                "provider": "firewall",
                "raw_message": f"action={row.get('action')} src={row.get('src_ip')}:{row.get('src_port')} dst={row.get('dst_ip')}:{row.get('dst_port')} proto={row.get('protocol')}",
                "event_data": {
                    "action": row.get("action"),
                    "interface": row.get("interface"),
                    "rule_id": row.get("rule_id"),
                    "bytes_in": row.get("bytes_in"),
                    "bytes_out": row.get("bytes_out")
                },
                "source_origin": "firewall.csv"
            }
            all_network_records.append(record)
            fw_count += 1
print(f"firewall.csv        : {fw_count:7} records normalized")

# 2. Process suricata_eve.json
sur_count = 0
sur_path = net_dir / "suricata_eve.json"
if sur_path.is_file():
    with sur_path.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                ts = normalize_time(data.get("timestamp"))
                alert = data.get("alert", {})
                
                sur_sev = alert.get("severity")
                severity = "info"
                if sur_sev == 1:
                    severity = "critical"
                elif sur_sev == 2:
                    severity = "medium"
                elif sur_sev == 3:
                    severity = "low"

                record = {
                    "timestamp": ts,
                    "hostname": data.get("host") or "suricata-sensor",
                    "source_type": "suricata",
                    "event_category": "network_alert",
                    "severity": severity,
                    "user": None,
                    "process_name": None,
                    "process_id": None,
                    "src_ip": data.get("src_ip"),
                    "src_port": data.get("src_port"),
                    "dst_ip": data.get("dest_ip"),
                    "dst_port": data.get("dst_port"),
                    "protocol": data.get("proto"),
                    "event_id": str(alert.get("signature_id")) if alert.get("signature_id") else None,
                    "provider": "suricata",
                    "raw_message": alert.get("signature") or line,
                    "event_data": {
                        "signature": alert.get("signature"),
                        "category": alert.get("category"),
                        "action": alert.get("action")
                    },
                    "source_origin": "suricata_eve.json"
                }
                all_network_records.append(record)
                sur_count += 1
            except json.JSONDecodeError:
                continue
print(f"suricata_eve.json   : {sur_count:7} records normalized")

# 3. Process pcap_summary.json
pcap_count = 0
pcap_path = net_dir / "pcap_summary.json"
if pcap_path.is_file():
    with pcap_path.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                ts = normalize_time(data.get("start_time"))
                record = {
                    "timestamp": ts,
                    "hostname": data.get("sensor_host") or "pcap-analyzer",
                    "source_type": "pcap",
                    "event_category": "network_flow",
                    "severity": "info",
                    "user": None,
                    "process_name": None,
                    "process_id": None,
                    "src_ip": data.get("src_ip"),
                    "src_port": data.get("src_port"),
                    "dst_ip": data.get("dst_ip"),
                    "dst_port": data.get("dst_port"),
                    "protocol": data.get("protocol"),
                    "event_id": None,
                    "provider": "pcap_summary",
                    "raw_message": data.get("summary") or f"Flow {data.get('src_ip')} -> {data.get('dst_ip')}",
                    "event_data": {
                        "end_time": data.get("end_time"),
                        "packet_count": data.get("packet_count"),
                        "byte_count": data.get("byte_count")
                    },
                    "source_origin": "pcap_summary.json"
                }
                all_network_records.append(record)
                pcap_count += 1
            except json.JSONDecodeError:
                continue
print(f"pcap_summary.json   : {pcap_count:7} records normalized")

# Write individual network events file
with network_only_file.open("w", encoding="utf-8") as f:
    for rec in all_network_records:
        f.write(json.dumps(rec, separators=(",", ":")) + "\n")

# Append to main normalized_events.json
with norm_file.open("a", encoding="utf-8") as f:
    for rec in all_network_records:
        f.write(json.dumps(rec, separators=(",", ":")) + "\n")

print("appended to normalized_events.json")
print("network_events.json written")
PY
