#!/usr/bin/env python3
import sys
import json
import sqlite3
import argparse
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_DB_PATH = "cases.db"

def get_connection(db_path: str = DEFAULT_DB_PATH) -> sqlite3.Connection:
    """Returns a SQLite connection with row_factory enabled."""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn

def init_db(db_path: str = DEFAULT_DB_PATH) -> None:
    """Creates the database and all tables if they do not exist."""
    conn = get_connection(db_path)
    cursor = conn.cursor()
    
    # Schema aligned with case_schema_reference.sql
    cursor.executescript("""
    CREATE TABLE IF NOT EXISTS cases (
        case_id TEXT PRIMARY KEY,
        alert_id TEXT NOT NULL,
        severity TEXT NOT NULL,
        title TEXT NOT NULL,
        description TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'open',
        resolution TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS case_iocs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        case_id TEXT NOT NULL,
        ioc_value TEXT NOT NULL,
        ioc_type TEXT NOT NULL,
        verdict TEXT NOT NULL,
        score INTEGER NOT NULL,
        FOREIGN KEY (case_id) REFERENCES cases (case_id)
    );

    CREATE TABLE IF NOT EXISTS case_notes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        case_id TEXT NOT NULL,
        note TEXT NOT NULL,
        created_at TEXT NOT NULL,
        FOREIGN KEY (case_id) REFERENCES cases (case_id)
    );
    """)
    conn.commit()
    conn.close()

def generate_case_id(db_path: str = DEFAULT_DB_PATH) -> str:
    """Generates a sequential case ID in format CASE-YYYYMMDD-NNN."""
    init_db(db_path)
    now_utc = datetime.now(timezone.utc)
    date_str = now_utc.strftime("%Y%m%d")
    prefix = f"CASE-{date_str}-"
    
    conn = get_connection(db_path)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT COUNT(*) FROM cases WHERE case_id LIKE ?",
        (f"{prefix}%",)
    )
    count = cursor.fetchone()[0]
    conn.close()
    
    seq = count + 1
    return f"{prefix}{seq:03d}"

def create_case(
    alert_id: str,
    severity: str,
    title: str,
    description: str,
    iocs: list[dict],
    db_path: str = DEFAULT_DB_PATH
) -> str:
    """Creates a new case, links IOCs, and returns the case_id."""
    init_db(db_path)
    case_id = generate_case_id(db_path)
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    
    conn = get_connection(db_path)
    cursor = conn.cursor()
    
    try:
        cursor.execute(
            """
            INSERT INTO cases (case_id, alert_id, severity, title, description, status, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, 'open', ?, ?)
            """,
            (case_id, alert_id, severity, title, description, now_str, now_str)
        )
        
        for ioc in iocs:
            cursor.execute(
                """
                INSERT INTO case_iocs (case_id, ioc_value, ioc_type, verdict, score)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    case_id,
                    ioc.get("ioc_value") or ioc.get("ioc", ""),
                    ioc.get("ioc_type") or ioc.get("type", "unknown"),
                    ioc.get("verdict", "INVESTIGATE"),
                    ioc.get("score", 0)
                )
            )
            
        conn.commit()
    except Exception as e:
        conn.rollback()
        raise e
    finally:
        conn.close()
        
    return case_id

def add_case_note(case_id: str, note: str, db_path: str = DEFAULT_DB_PATH) -> bool:
    """Appends a note to a case and updates updated_at timestamp."""
    init_db(db_path)
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    
    conn = get_connection(db_path)
    cursor = conn.cursor()
    
    cursor.execute("SELECT 1 FROM cases WHERE case_id = ?", (case_id,))
    if not cursor.fetchone():
        conn.close()
        return False
        
    cursor.execute(
        "INSERT INTO case_notes (case_id, note, created_at) VALUES (?, ?, ?)",
        (case_id, note, now_str)
    )
    cursor.execute(
        "UPDATE cases SET updated_at = ? WHERE case_id = ?",
        (now_str, case_id)
    )
    
    conn.commit()
    conn.close()
    return True

def update_case_status(case_id: str, status: str, db_path: str = DEFAULT_DB_PATH) -> bool:
    """Updates case status if valid ('open', 'investigating', 'escalated', 'closed')."""
    valid_statuses = {"open", "investigating", "escalated", "closed"}
    if status not in valid_statuses:
        return False
        
    init_db(db_path)
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    
    conn = get_connection(db_path)
    cursor = conn.cursor()
    
    cursor.execute("SELECT 1 FROM cases WHERE case_id = ?", (case_id,))
    if not cursor.fetchone():
        conn.close()
        return False
        
    cursor.execute(
        "UPDATE cases SET status = ?, updated_at = ? WHERE case_id = ?",
        (status, now_str, case_id)
    )
    conn.commit()
    conn.close()
    return True

def close_case(case_id: str, resolution: str, db_path: str = DEFAULT_DB_PATH) -> bool:
    """Closes a case with a resolution string."""
    init_db(db_path)
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    
    conn = get_connection(db_path)
    cursor = conn.cursor()
    
    cursor.execute("SELECT 1 FROM cases WHERE case_id = ?", (case_id,))
    if not cursor.fetchone():
        conn.close()
        return False
        
    cursor.execute(
        "UPDATE cases SET status = 'closed', resolution = ?, updated_at = ? WHERE case_id = ?",
        (resolution, now_str, case_id)
    )
    conn.commit()
    conn.close()
    return True

def get_case(case_id: str, db_path: str = DEFAULT_DB_PATH) -> dict | None:
    """Retrieves full case details including nested notes and IOCs."""
    init_db(db_path)
    conn = get_connection(db_path)
    cursor = conn.cursor()
    
    cursor.execute("SELECT * FROM cases WHERE case_id = ?", (case_id,))
    row = cursor.fetchone()
    if not row:
        conn.close()
        return None
        
    case_dict = dict(row)
    
    cursor.execute("SELECT ioc_value, ioc_type, verdict, score FROM case_iocs WHERE case_id = ?", (case_id,))
    case_dict["iocs"] = [dict(r) for r in cursor.fetchall()]
    
    cursor.execute("SELECT note, created_at FROM case_notes WHERE case_id = ?", (case_id,))
    case_dict["notes"] = [dict(r) for r in cursor.fetchall()]
    
    conn.close()
    return case_dict

def list_cases(status: str = None, db_path: str = DEFAULT_DB_PATH) -> list[dict]:
    """Lists case summaries, optionally filtered by status."""
    init_db(db_path)
    conn = get_connection(db_path)
    cursor = conn.cursor()
    
    if status:
        cursor.execute(
            "SELECT case_id, alert_id, severity, title, status, created_at FROM cases WHERE status = ? ORDER BY created_at DESC",
            (status,)
        )
    else:
        cursor.execute(
            "SELECT case_id, alert_id, severity, title, status, created_at FROM cases ORDER BY created_at DESC"
        )
        
    cases = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return cases

def main():
    parser = argparse.ArgumentParser(description="SOC Case Manager CLI")
    subparsers = parser.add_subparsers(dest="command", help="Command to execute")
    
    # list parser
    parser_list = subparsers.add_parser("list", help="List cases")
    parser_list.add_argument("--status", help="Filter by status (open, investigating, escalated, closed)")
    parser_list.add_argument("--db", default=DEFAULT_DB_PATH, help="Path to SQLite DB")
    
    # get parser
    parser_get = subparsers.add_parser("get", help="Get full case details")
    parser_get.add_argument("case_id", help="Case ID to retrieve")
    parser_get.add_argument("--db", default=DEFAULT_DB_PATH, help="Path to SQLite DB")
    
    # close parser
    parser_close = subparsers.add_parser("close", help="Close a case")
    parser_close.add_argument("case_id", help="Case ID to close")
    parser_close.add_argument("resolution", help="Resolution description")
    parser_close.add_argument("--db", default=DEFAULT_DB_PATH, help="Path to SQLite DB")
    
    args = parser.parse_args()
    init_db(args.db if hasattr(args, "db") else DEFAULT_DB_PATH)
    
    if args.command == "list":
        cases = list_cases(status=args.status, db_path=args.db)
        
        # Print table header
        print(f"+{'-'*21}+{'-'*21}+{'-'*10}+{'-'*40}+{'-'*11}+")
        print(f"| {'Case ID':<19} | {'Alert ID':<19} | {'Severity':<8} | {'Title':<38} | {'Status':<9} |")
        print(f"+{'-'*21}+{'-'*21}+{'-'*10}+{'-'*40}+{'-'*11}+")
        
        for c in cases:
            print(f"| {c['case_id']:<19} | {c['alert_id']:<19} | {c['severity']:<8} | {c['title']:<38} | {c['status']:<9} |")
            
        print(f"+{'-'*21}+{'-'*21}+{'-'*10}+{'-'*40}+{'-'*11}+")
        filter_label = f"filter: {args.status}" if args.status else "all cases"
        print(f"{len(cases)} cases ({filter_label})")
        
    elif args.command == "get":
        case_data = get_case(args.case_id, db_path=args.db)
        if case_data:
            print(json.dumps(case_data, indent=2))
        else:
            print(f"Error: Case {args.case_id} not found.", file=sys.stderr)
            sys.exit(1)
            
    elif args.command == "close":
        success = close_case(args.case_id, args.resolution, db_path=args.db)
        if success:
            print(f"Case {args.case_id} successfully closed.")
        else:
            print(f"Error: Case {args.case_id} not found.", file=sys.stderr)
            sys.exit(1)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
