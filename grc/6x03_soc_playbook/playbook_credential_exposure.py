#!/usr/bin/env python3
import sys
import json
import argparse
from datetime import datetime, timezone
from pathlib import Path

try:
    from enrich_ioc import enrich_ioc
    import case_manager
except ImportError as e:
    print(f"Error importing required local modules: {e}", file=sys.stderr)
    sys.exit(1)

# MITRE ATT&CK Mapping Reference
MITRE_TECHNIQUES = {
    "T1003.001": "LSASS Memory",
    "T1550.002": "Pass the Hash",
    "T1021.002": "SMB/Windows Admin Shares",
    "T1059.001": "PowerShell"
}

def load_privileged_accounts(path: str = "privileged_accounts.json") -> tuple[set, set]:
    """Loads domain admins and server admins from privileged_accounts.json."""
    domain_admins = set()
    server_admins = set()
    try:
        with open(path, "r") as f:
            data = json.load(f)
            # Handle list or dict structures commonly found in IAM inventories
            if isinstance(data, dict):
                domain_admins = set(data.get("domain_admins", []))
                server_admins = set(data.get("server_admins", []))
            elif isinstance(data, list):
                for group in data:
                    name = group.get("group_name", "").lower()
                    members = group.get("members", [])
                    if "domain" in name or "da" in name:
                        domain_admins.update(members)
                    elif "server" in name or "sa" in name:
                        server_admins.update(members)
    except Exception as e:
        print(f"Warning: Could not load privileged accounts inventory from {path}: {e}", file=sys.stderr)
    return domain_admins, server_admins

def append_to_isolation_queue(entry: dict, queue_path: str = "isolation_queue.json") -> None:
    """Appends an isolation queue entry to isolation_queue.json, creating it if needed."""
    queue = []
    path = Path(queue_path)
    if path.exists():
        try:
            with open(path, "r") as f:
                content = f.read().strip()
                if content:
                    queue = json.loads(content)
        except Exception as e:
            print(f"Warning: Failed to read existing isolation queue: {e}", file=sys.stderr)
            queue = []
            
    queue.append(entry)
    try:
        with open(path, "w") as f:
            json.dump(queue, f, indent=2)
    except Exception as e:
        print(f"Error: Failed to write to isolation queue {queue_path}: {e}", file=sys.stderr)
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description="Credential Exposure Automation Playbook")
    parser.add_argument("alert_path", help="Path to credential alert JSON file")
    parser.add_argument("--priv-accounts", default="privileged_accounts.json", help="Path to privileged accounts JSON")
    args = parser.parse_args()

    # 1. Load Alert JSON
    try:
        with open(args.alert_path, "r") as f:
            alert = json.load(f)
    except Exception as e:
        print(f"Error: Unrecoverable error reading alert file {args.alert_path}: {e}", file=sys.stderr)
        sys.exit(1)

    alert_id = alert.get("alert_id") or alert.get("id")
    if not alert_id:
        print("Error: Missing required field 'alert_id' in alert JSON", file=sys.stderr)
        sys.exit(1)

    rule_name = alert.get("rule_name") or alert.get("rule", "credential_access_lsass_dump")
    raw_log = alert.get("raw_log", {})

    source_ip = raw_log.get("source_ip", "").strip()
    username = raw_log.get("username", "").strip()
    host = raw_log.get("host", "").strip()
    mitre_id = raw_log.get("mitre_technique", "").strip()
    mitre_name = MITRE_TECHNIQUES.get(mitre_id, raw_log.get("mitre_name", "Unknown Technique"))

    # 2. Enrich source_ip
    enrichment_result = {}
    ip_verdict = "ALLOW"
    if source_ip:
        try:
            enrichment_result = enrich_ioc(source_ip)
            ip_verdict = enrichment_result.get("verdict", "ALLOW")
        except Exception as e:
            print(f"Warning: enrich_ioc failed for source_ip {source_ip}: {e}", file=sys.stderr)
            ip_verdict = "INVESTIGATE"
            enrichment_result = {"ioc": source_ip, "verdict": "INVESTIGATE", "score": 30}

    # 3. Check Privileged Accounts
            domain_admins, server_admins = load_privileged_accounts(args.priv_accounts)
    is_da = username in domain_admins
    is_sa = username in server_admins or is_da # Domain admins are often also server admins

    # 4. Decision Logic Matrix
    # Matrix mapping:
    # BLOCK + Any DA/SA -> Critical, escalate, write to isolation queue
    # INVESTIGATE + DA (True) -> Critical, escalate, write to isolation queue
    # INVESTIGATE + DA (False) + SA (True/False) -> High, manual review (no isolation queue)
    # ALLOW + DA (True) -> High, escalate: privileged account anomaly, write to isolation queue (or escalate with queue)
    # ALLOW + SA (True) -> Medium, manual review
    # ALLOW + False/False -> Medium, manual review
    
    write_to_queue = False
    if ip_verdict == "BLOCK":
        playbook_verdict = "ESCALATE"
        case_severity = "Critical"
        case_status = "escalated"
        write_to_queue = True
        action_desc = "Host flagged and queued for analyst-authorized EDR isolation"
    elif ip_verdict == "INVESTIGATE" and is_da:
        playbook_verdict = "ESCALATE"
        case_severity = "Critical"
        case_status = "escalated"
        write_to_queue = True
        action_desc = "Host flagged and queued for analyst-authorized EDR isolation (Investigate IP + Domain Admin)"
    elif ip_verdict == "INVESTIGATE":
        playbook_verdict = "REVIEW"
        case_severity = "High"
        case_status = "open"
        action_desc = "Queued for manual analyst review"
    elif ip_verdict == "ALLOW" and is_da:
        playbook_verdict = "ESCALATE"
        case_severity = "High"
        case_status = "escalated"
        write_to_queue = True
        action_desc = "Privileged account anomaly from internal IP; queued for isolation review"
    else:
        playbook_verdict = "REVIEW"
        case_severity = "Medium"
        case_status = "open"
        action_desc = "Queued for standard review"

    # 5. Create Case and Link IOCs
    case_title = alert.get("title") or f"Credential Access: {rule_name.replace('_', ' ').title()} on {host}"
    case_desc = alert.get("description") or f"Alert {alert_id}: User {username} performed {mitre_id} ({mitre_name}) from source {source_ip}."

    case_iocs = []
    if source_ip:
        case_iocs.append({
            "ioc_value": source_ip,
            "ioc_type": enrichment_result.get("type", "ipv4"),
            "verdict": ip_verdict,
            "score": enrichment_result.get("score", 0)
        })

    try:
        case_id = case_manager.create_case(
            alert_id=alert_id,
            severity=case_severity,
            title=case_title,
            description=case_desc,
            iocs=case_iocs
        )
    except Exception as e:
        print(f"Error: Failed to create case in database: {e}", file=sys.stderr)
        sys.exit(1)

    # Add detailed case note
    note_text = (
        f"Credential Exposure Playbook Execution:\n"
        f"- Source IP: {source_ip} (Verdict: {ip_verdict}, Score: {enrichment_result.get('score', 0)})\n"
        f"- User: {username} (Domain Admin: {is_da}, Server Admin: {is_sa})\n"
        f"- Target Host: {host}\n"
        f"- Technique: {mitre_id} - {mitre_name}\n"
        f"- Verdict: {playbook_verdict} (Severity: {case_severity})"
    )
    case_manager.add_case_note(case_id, note_text)

    if playbook_verdict == "ESCALATE":
        case_manager.update_case_status(case_id, "escalated")

    # 6. Write to Isolation Queue if required
    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    if write_to_queue and host:
        queue_entry = {
            "queued_at": now_iso,
            "host": host,
            "alert_id": alert_id,
            "case_id": case_id,
            "reason": f"{mitre_name} ({mitre_id}) from IP {source_ip} (verdict: {ip_verdict}) by user {username} (DA: {is_da})",
            "action_required": "Analyst must authorize isolation via EDR console before execution",
            "status": "pending_authorization"
        }
        append_to_isolation_queue(queue_entry)

    # 7. Audit Logging
    audit_line = f"{now_iso} | CREDENTIAL_EXPOSURE | {alert_id} | IP:{source_ip} | Verdict:{ip_verdict} | User:{username}(DA:{is_da}) | Case:{case_id} | Severity:{case_severity}"
    try:
        with open("playbook_audit.log", "a") as log_f:
            log_f.write(audit_line + "\n")
    except Exception as e:
        print(f"Warning: Failed to write to playbook_audit.log: {e}", file=sys.stderr)

    # 8. Print Structured Operator Summary
    print(f"[{now_iso}] CREDENTIAL EXPOSURE PLAYBOOK")
    print(f"Alert      : {alert_id}")
    print(f"Rule       : {rule_name}")
    print(f"Host       : {host}")
    print(f"User       : {username} (Domain Admin: {is_da}, Server Admin: {is_sa})")
    print(f"Technique  : {mitre_id} - {mitre_name}")
    print(f"Source IP  : {source_ip:<15} verdict={ip_verdict} score={enrichment_result.get('score', 0)}")
    print(f"Verdict    : {playbook_verdict}")
    print(f"Case       : {case_id}  Severity: {case_severity}  Status: {case_status}")
    print(f"Action     : {action_desc}")

if __name__ == "__main__":
    main()
