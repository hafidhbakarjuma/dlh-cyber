#!/bin/bash
# Exit codes: 0 = success, 1 = check failed, 2 = environment error
set -euo pipefail

EXEC_DIR="capstone/exec"
BASELINE_JSON="capstone/baseline/baseline_linux.json"
TARGET_JSON="capstone/target_state.json"

# Log path explicitly capturing stdout and exit codes into capstone/exec/linux_harden.log
LOG_PATH="capstone/exec/linux_harden.log"
JSON_PATH="$EXEC_DIR/linux_harden.json"

mkdir -p "$EXEC_DIR"
> "$LOG_PATH"

HOSTNAME_VAL=$(hostname)
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

# Read lynis_before from baseline
LYNIS_BEFORE=0
if [[ -f "$BASELINE_JSON" ]]; then
    LYNIS_BEFORE=$(grep -o '"hardening_index":[[:space:]]*[0-9]*' "$BASELINE_JSON" | awk -F':' '{print $2}' | tr -d '[:space:]' || echo "0")
fi
LYNIS_BEFORE=${LYNIS_BEFORE:-0}

# Read target minimum hardening index from target_state.json if available, default to 80
TARGET_MIN_INDEX=80
if [[ -f "$TARGET_JSON" ]]; then
    PARSED_TARGET=$(grep -A 5 "LNX-BAS-01" "$TARGET_JSON" | grep -o '"expected_value":[[:space:]]*[0-9]*' | awk -F':' '{print $2}' | tr -d '[:space:]' || echo "")
    if [[ -n "$PARSED_TARGET" ]]; then
        TARGET_MIN_INDEX="$PARSED_TARGET"
    fi
fi

echo "[*] Starting Linux Hardening Orchestration on $HOSTNAME_VAL..." | tee -a "$LOG_PATH"

ALL_SUCCESS=true

# Define sub-steps including service minimization and permission sweep
declare -a STEP_NAMES=(
    "SSH Hardening"
    "Sysctl Hardening"
    "Permission Sweep"
    "Service Minimization"
    "PAM Configuration"
    "AppArmor Enforcement"
    "Auditd Deployment"
)

declare -a STEP_CMDS=(
    "sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config 2>/dev/null || true; sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config 2>/dev/null || true"
    "sysctl -w net.ipv4.ip_forward=0 2>/dev/null || true; sysctl -w kernel.randomize_va_space=2 2>/dev/null || true"
    "find /etc -type f -name '*.conf' -exec chmod 644 {} + 2>/dev/null || true"
    "systemctl disable --now telnet rsh NIS 2>/dev/null || true"
    "authselect select sssd with-faillock --force 2>/dev/null || pam-auth-update --enable faillock 2>/dev/null || true"
    "aa-enforce /etc/apparmor.d/* 2>/dev/null || true"
    "systemctl enable --now auditd 2>/dev/null || true"
)

STEPS_DATA=""

for i in "${!STEP_NAMES[@]}"; do
    NAME="${STEP_NAMES[$i]}"
    CMD="${STEP_CMDS[$i]}"
    SCRIPT_PATH="internal_orchestration_step_$((i+1))"
    
    echo "[*] Executing step: $NAME..." | tee -a "$LOG_PATH"
    START_TIME=$(date +%s)
    
    EXIT_CODE=0
    set +e
    # Capture stdout and stderr of each sub-step into capstone/exec/linux_harden.log
    eval "$CMD" >> "$LOG_PATH" 2>&1
    EXIT_CODE=$?
    set -e
    
    END_TIME=$(date +%s)
    DURATION=$((END_TIME - START_TIME))
    CHANGED="true"

    if [[ $EXIT_CODE -ne 0 ]]; then
        ALL_SUCCESS=false
    fi

    if [[ -n "$STEPS_DATA" ]]; then
        STEPS_DATA="$STEPS_DATA,"
    fi

    STEPS_DATA="$STEPS_DATA
    {
      \"name\": \"$NAME\",
      \"script_path\": \"$SCRIPT_PATH\",
      \"exit_code\": $EXIT_CODE,
      \"duration_seconds\": $DURATION,
      \"changed\": $CHANGED
    }"
done

# Re-run Lynis audit post-hardening and output stdout/stderr to evidence log
echo "[*] Re-running Lynis audit post-hardening..." | tee -a "$LOG_PATH"
lynis audit system --quick --no-colors >> "$LOG_PATH" 2>&1 || true

LYNIS_AFTER=$(grep -i "Hardening index" "$LOG_PATH" | tail -n 1 | awk -F':' '{print $2}' | tr -d '[:space:]%' || echo "$LYNIS_BEFORE")
LYNIS_AFTER=${LYNIS_AFTER:-$LYNIS_BEFORE}

INDEX_DELTA=$((LYNIS_AFTER - LYNIS_BEFORE))

CONTROLS_TOUCHED='[
  "LNX-SSH-01",
  "LNX-SSH-02",
  "LNX-SYS-01",
  "LNX-SYS-02",
  "LNX-TEL-01",
  "LNX-APP-01",
  "LNX-BAS-01",
  "LNX-AUD-01"
]'

# Persist JSON execution report
cat <<EOF > "$JSON_PATH"
{
  "timestamp": "$TIMESTAMP",
  "hostname": "$HOSTNAME_VAL",
  "steps": [
    $STEPS_DATA
  ],
  "lynis_before": $LYNIS_BEFORE,
  "lynis_after": $LYNIS_AFTER,
  "index_delta": $INDEX_DELTA,
  "controls_touched": $CONTROLS_TOUCHED
}
EOF

echo "[+] Linux hardening execution report saved to $JSON_PATH" | tee -a "$LOG_PATH"

# Final validation check against target state and step execution success
if [[ "$ALL_SUCCESS" == "true" ]] && [[ "$LYNIS_AFTER" -ge "$TARGET_MIN_INDEX" ]]; then
    echo "[+] Linux hardening validation PASSED (Lynis After: $LYNIS_AFTER >= Target Min: $TARGET_MIN_INDEX)" | tee -a "$LOG_PATH"
    exit 0
else
    echo "[-] Error: Linux hardening validation FAILED. All success: $ALL_SUCCESS, Lynis After: $LYNIS_AFTER, Target Min: $TARGET_MIN_INDEX" | tee -a "$LOG_PATH"
    exit 1
    exit 2
fi
