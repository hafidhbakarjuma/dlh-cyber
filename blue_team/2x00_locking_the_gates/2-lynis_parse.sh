#!/bin/bash
set -euo pipefail

# Task 2: The Lynis Audit Parser
# Script: 2-lynis_parse.sh
# Description: Parses a Lynis report file (.dat) and outputs a structured JSON summary on stdout.

REPORT_FILE="${1:-/var/log/lynis-report.dat}"

if [ ! -f "$REPORT_FILE" ]; then
    echo "[-] Error: Report file '$REPORT_FILE' not found." >&2
    exit 1
fi

if [ ! -r "$REPORT_FILE" ]; then
    echo "[-] Error: Permission denied reading '$REPORT_FILE'. Try running with sudo." >&2
    exit 1
fi

python3 - "$REPORT_FILE" << 'EOF'
import sys
import json

report_path = sys.argv[1]
hardening_index = 0
findings = []

with open(report_path, 'r', encoding='utf-8', errors='ignore') as f:
    for line in f:
        line = line.strip()
        if line.startswith('hardening_index='):
            try:
                hardening_index = int(line.split('=', 1)[1].strip())
            except ValueError:
                pass
        elif line.startswith('warning[]='):
            val = line.split('=', 1)[1]
            parts = val.split('|', 1)
            findings.append({
                "severity": "warning",
                "test_id": parts[0].strip(),
                "message": parts[1].strip() if len(parts) > 1 else ""
            })
        elif line.startswith('suggestion[]='):
            val = line.split('=', 1)[1]
            parts = val.split('|', 1)
            findings.append({
                "severity": "suggestion",
                "test_id": parts[0].strip(),
                "message": parts[1].strip() if len(parts) > 1 else ""
            })
        elif line.startswith('manual_check[]='):
            val = line.split('=', 1)[1]
            parts = val.split('|', 1)
            findings.append({
                "severity": "manual_check",
                "test_id": parts[0].strip(),
                "message": parts[1].strip() if len(parts) > 1 else ""
            })

output = {
    "hardening_index": hardening_index,
    "findings": findings
}

print(json.dumps(output, indent=2))
EOF
