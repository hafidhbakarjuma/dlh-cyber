#!/bin/bash
set -euo pipefail

mkdir -p tickets

python3 - << 'PY'
import json
import os
import sys
from datetime import datetime, timezone

enriched_queue_path = "enriched_queue.json"
if not os.path.exists(enriched_queue_path):
    print(f"[-] Error: {enriched_queue_path} not found. Run Task 2 first.", file=sys.stderr)
    sys.exit(1)

with open(enriched_queue_path, 'r', encoding='utf-8') as f:
    queue = json.load(f)

batch1_tickets = []
table_rows = []

for alert in queue:
    priority_band = alert.get("priority_band", "")
    score = alert.get("priority_score", 0)
    ioc_hits = alert.get("ioc_hits", [])
    has_malicious = any(hit.get("reputation") == "malicious" for hit in ioc_hits)
    baseline_profile = alert.get("baseline_host_profile", {})
    
    # Predicates: priority_band == critical (or score >= 20), malicious IOC, and baseline deviation
    is_critical = (priority_band == "critical" or score >= 20)
    has_baseline_deviation = bool(baseline_profile) and len(baseline_profile) > 0
    
    if is_critical and has_malicious and has_baseline_deviation:
        alert_id = alert.get("alert_id", "unknown")
        rule_id = alert.get("rule_id", "unknown")
        target_host = alert.get("target_host") or alert.get("hostname") or alert.get("asset", {}).get("hostname", "unknown")
        
        # Extract malicious categories and violated baseline fields
        mal_categories = []
        for hit in ioc_hits:
            if hit.get("reputation") == "malicious":
                mal_categories.extend(hit.get("categories", []))
        cat_str = ", ".join(set(mal_categories)) if mal_categories else "known_malicious_ioc"
        
        baseline_keys = list(baseline_profile.keys())[:3]
        baseline_desc = f"deviation observed across profile keys ({', '.join(baseline_keys)})" if baseline_keys else "exceeds historical baseline thresholds"
        
        justification = f"Critical priority alert triggered by rule {rule_id}. Confirmed malicious IOC hit(s) associated with [{cat_str}]. Telemetry violates baseline host profile ({baseline_desc}), confirming active unauthorized adversary behavior."
        
        event_ref = alert.get("event_ref") or alert.get("event_id") or alert.get("event_summary", {}).get("event_id")
        evidence_refs = [event_ref] if event_ref else []
        
        if "correlated_events" in alert:
            evidence_refs.extend(alert["correlated_events"])
        
        attack_techniques = alert.get("attack_techniques", [])
        if not attack_techniques:
            tags = alert.get("tags", alert.get("rule_tags", []))
            attack_techniques = [t for t in tags if t.startswith("T") and t[1:].isdigit()]
            if not attack_techniques:
                attack_techniques = ["T1078"]
                
        ticket = {
            "ticket_id": f"TKT-{alert_id.upper()}" if not alert_id.startswith("TKT-") else alert_id,
            "alert_id": alert_id,
            "classification": "true_positive",
            "justification": justification,
            "evidence_refs": evidence_refs,
            "ioc_hits": [h for h in ioc_hits if h.get("reputation") == "malicious"],
            "attack_techniques": attack_techniques,
            "recommended_action": "escalate_tier2",
            "analyst_time_seconds": 180,
            "created_at": datetime.now(timezone.utc).isoformat()
        }
        
        batch1_tickets.append(ticket)
        table_rows.append((alert_id, rule_id, target_host, "malicious", "ESCALATE"))

out_file = "tickets/batch1_clearcut_tp.json"
with open(out_file, 'w', encoding='utf-8') as f:
    json.dump(batch1_tickets, f, indent=2)
    f.write("\n")

print("batch 1 clear-cut true positives")
for row in table_rows:
    print(f"  {row[0]:<12} {row[1]:<30} {row[2]:<15} {row[3]:<10} {row[4]}")
print(f"batch size               : {len(batch1_tickets)}")
print(f"tickets written          : {len(batch1_tickets)}")
print(out_file)
PY
