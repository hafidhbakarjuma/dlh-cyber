#!/bin/bash
# Exit codes: 0 = success, 1 = check failed, 2 = environment error
set -euo pipefail

mkdir -p capstone/baseline

LOG_PATH="capstone/baseline/lynis_baseline.log"
JSON_PATH="capstone/baseline/baseline_linux.json"

if ! command -v lynis &> /dev/null; then
    echo "[-] Error: lynis audit tool is not installed." >&2
    exit 2
fi

echo "[*] Running Lynis baseline audit..."
lynis audit system --quick --no-colors > capstone/baseline/lynis_baseline.log 2>&1 || true

# Parse metrics from the generated lynis log
LYNIS_VERSION=$(grep -i "lynis version" capstone/baseline/lynis_baseline.log | awk '{print $3}' || echo "Unknown")
HARDENING_INDEX=$(grep -i "Hardening index" capstone/baseline/lynis_baseline.log | awk '{print $3}' | tr -d '%' || echo "0")
WARNINGS_COUNT=$(grep -i "Warning:" capstone/baseline/lynis_baseline.log | wc -l || echo "0")
SUGGESTIONS_COUNT=$(grep -i "Suggestion:" capstone/baseline/lynis_baseline.log | wc -l || echo "0")
HOSTNAME_VAL=$(hostname)
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

cat <<EOF > capstone/baseline/baseline_linux.json
{
  "timestamp": "$TIMESTAMP",
  "hostname": "$HOSTNAME_VAL",
  "lynis_version": "$LYNIS_VERSION",
  "hardening_index": ${HARDENING_INDEX:-0},
  "warnings_count": $WARNINGS_COUNT,
  "suggestions_count": $SUGGESTIONS_COUNT,
  "log_path": "capstone/baseline/lynis_baseline.log"
}
EOF

echo "[+] Linux baseline snapshot successfully persisted to capstone/baseline/baseline_linux.json"
exit 0
exit 1
