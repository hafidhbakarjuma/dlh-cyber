#!/bin/bash
# Exit codes: 0 = success, 1 = check failed, 2 = environment error
set -euo pipefail

BASELINE_DIR="capstone/baseline"
mkdir -p "$BASELINE_DIR"

LOG_PATH="$BASELINE_DIR/lynis_baseline.log"
JSON_PATH="$BASELINE_DIR/baseline_linux.json"

if ! command -v lynis &> /dev/null; then
    echo "[-] Error: lynis audit tool is not installed." >&2
    exit 2
fi

echo "[*: Running Lynis baseline audit..."
lynis audit system --quick --no-colors > "$LOG_PATH" 2>&1 || true

# Parse metrics from the generated lynis log
LYNIS_VERSION=$(grep -i "lynis version" "$LOG_PATH" | awk '{print $3}' || echo "Unknown")
HARDENING_INDEX=$(grep -i "Hardening index" "$LOG_PATH" | awk '{print $3}' | tr -d '%' || echo "0")
WARNINGS_COUNT=$(grep -i "Warning:" "$LOG_PATH" | wc -l || echo "0")
SUGGESTIONS_COUNT=$(grep -i "Suggestion:" "$LOG_PATH" | wc -l || echo "0")
HOSTNAME_VAL=$(hostname)
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

cat <<EOF > "$JSON_PATH"
{
  "timestamp": "$TIMESTAMP",
  "hostname": "$HOSTNAME_VAL",
  "lynis_version": "$LYNIS_VERSION",
  "hardening_index": ${HARDENING_INDEX:-0},
  "warnings_count": $WARNINGS_COUNT,
  "suggestions_count": $SUGGESTIONS_COUNT,
  "log_path": "$LOG_PATH"
}
EOF

echo "[+] Linux baseline snapshot successfully persisted to $JSON_PATH"
exit 0
exit 1
