#!/bin/bash
set -euo pipefail

# Determine base evidence pack path from argument or default safely
EVIDENCE_DIR="${1:-/home/student/evidence_pack_primary}"
CONTEXT_DIR="${EVIDENCE_DIR}/context"

python3 - "$CONTEXT_DIR" << 'PY'
import sys
import json
import ipaddress
from pathlib import Path

context_dir = Path(sys.argv[1])
cleaned_file = Path("cleaned_events.json")
enriched_file = Path("enriched_events.json")

inventory_path = context_dir / "asset_inventory.json"
zones_path = context_dir / "network_zones.json"

# Load Asset Inventory (mapping hostname -> asset info)
asset_inventory = {}
if inventory_path.is_file():
    with inventory_path.open("r", encoding="utf-8") as f:
        try:
            data = json.load(f)
            # Handle if inventory is list or dict
            if isinstance(data, list):
                for item in data:
                    h = item.get("hostname") or item.get("host")
                    if h:
                        asset_inventory[h.lower()] = item
            elif isinstance(data, dict):
                for h, item in data.items():
                    asset_inventory[h.lower()] = item
        except Exception:
            pass

# Load Network Zones (CIDR mappings)
zone_networks = []
if zones_path.is_file():
    with zones_path.open("r", encoding="utf-8") as f:
        try:
            data = json.load(f)
            # Support list format or dict format containing cidr/zone
            items = data if isinstance(data, list) else data.get("zones", [])
            for item in items:
                cidr_str = item.get("cidr") or item.get("network")
                zone_name = item.get("zone") or item.get("name")
                if cidr_str and zone_name:
                    try:
                        net = ipaddress.ip_network(cidr_str, strict=False)
                        zone_networks.append((net, zone_name))
                    except ValueError:
                        pass
        except Exception:
            pass

def resolve_zone(ip_str):
    if not ip_str:
        return "unknown"
    try:
        ip_obj = ipaddress.ip_address(ip_str.strip())
        for net, zone in zone_networks:
            if ip_obj in net:
                return zone
    except ValueError:
        pass
    return "unknown"

total_events = 0
asset_matched = 0
src_resolved = 0
dst_resolved = 0
unknown_hosts_set = set()

enriched_records = []

if cleaned_file.is_file():
    with cleaned_file.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue

            total_events += 1

            # Asset Enrichment
            hostname = rec.get("hostname")
            if hostname:
                h_lower = str(hostname).lower()
                if h_lower in asset_inventory:
                    inv = asset_inventory[h_lower]
                    rec["asset"] = {
                        "role": inv.get("role"),
                        "criticality": inv.get("criticality"),
                        "os": inv.get("os"),
                        "owner": inv.get("owner"),
                        "zone": inv.get("zone")
                    }
                    asset_matched += 1
                else:
                    rec["asset"] = {
                        "role": "unknown",
                        "criticality": "unknown",
                        "os": "unknown",
                        "owner": "unknown",
                        "zone": "unknown"
                    }
                    unknown_hosts_set.add(hostname)
            else:
                rec["asset"] = {
                    "role": "unknown",
                    "criticality": "unknown",
                    "os": "unknown",
                    "owner": "unknown",
                    "zone": "unknown"
                }

            # Zone Enrichment
            src_ip = rec.get("src_ip")
            dst_ip = rec.get("dst_ip")

            src_z = resolve_zone(src_ip)
            dst_z = resolve_zone(dst_ip)

            rec["src_zone"] = src_z
            rec["dst_zone"] = dst_z

            if src_ip and src_z != "unknown":
                src_resolved += 1
            if dst_ip and dst_z != "unknown":
                dst_resolved += 1

            enriched_records.append(rec)

# Write enriched dataset
with enriched_file.open("w", encoding="utf-8") as f:
    for rec in enriched_records:
        f.write(json.dumps(rec, separators=(",", ":")) + "\n")

# Calculate metrics
asset_pct = f"{(asset_matched / total_events * 100):.1f}" if total_events > 0 else "0.0"
src_pct = f"{(src_resolved / total_events * 100):.1f}" if total_events > 0 else "0.0"
dst_pct = f"{(dst_resolved / total_events * 100):.1f}" if total_events > 0 else "0.0"

print(f"events processed    : {total_events}")
print(f"asset context added : {asset_matched} ({asset_pct}%)")
print(f"src_zone resolved   : {src_resolved} ({src_pct}%)")
print(f"dst_zone resolved   : {dst_resolved} ({dst_pct}%)")
print(f"unknown hosts       : {len(unknown_hosts_set)}")
print("enriched_events.json written")
PY
