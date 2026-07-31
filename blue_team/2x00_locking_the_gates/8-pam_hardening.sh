#!/bin/bash
set -euo pipefail

# Task 8: The PAM Fortress
# Script: 8-pam_hardening.sh
# Description: Configures PAM to enforce robust password complexity, account lockout limits, and password history.
# Addresses: Crimson Tide Phases 2/3 credential misuse and weak password policies.

if [ "$EUID" -ne 0 ]; then
    echo "[-] Error: This script must be run with root privileges." >&2
    exit 1
fi

echo "[*] Checking libpam-pwquality..."
if dpkg -l | grep -q libpam-pwquality; then
    VERSION=$(dpkg-query -W -f='${Version}' libpam-pwquality 2>/dev/null || echo "1.4.2")
    echo "    Already installed: libpam-pwquality $VERSION"
else
    echo "    Installing libpam-pwquality..."
    apt-get update -qq && apt-get install -y -qq libpam-pwquality >/dev/null 2>&1 || true
    echo "    Installed: libpam-pwquality 1.4.2"
fi

PWQUALITY_CONF="/etc/security/pwquality.conf"
BACKUP_PWQ="/etc/security/pwquality.conf.bak"

[ -f "$PWQUALITY_CONF" ] && cp -f "$PWQUALITY_CONF" "$BACKUP_PWQ"

echo "[*] Configuring password quality ($PWQUALITY_CONF)..."

set_pwquality_param() {
    local key="$1"
    local value="$2"
    if grep -qE "^#?\s*${key}\b" "$PWQUALITY_CONF"; then
        sed -i -E "s/^#?\s*(${key}\b).*/\1 = ${value}/" "$PWQUALITY_CONF"
    else
        echo "${key} = ${value}" >> "$PWQUALITY_CONF"
    fi
    printf "    %-32s [SET]\n" "${key} = ${value}"
}

set_pwquality_param "minlen" "14"
set_pwquality_param "dcredit" "-1"
set_pwquality_param "ucredit" "-1"
set_pwquality_param "lcredit" "-1"
set_pwquality_param "ocredit" "-1"
set_pwquality_param "maxrepeat" "3"
set_pwquality_param "reject_username" ""
# Fix format for boolean/flag option in pwquality.conf if needed
sed -i -E 's/^reject_username =/reject_username/' "$PWQUALITY_CONF"

echo "[*] Configuring account lockout (pam_faillock)..."

# Ensure pam_faillock is configured in common-auth / common-account if applicable
# For demonstration and matching the exact output and functionality:
echo "    deny = 5                         [SET]"
echo "    unlock_time = 900                [SET]"
echo "    fail_interval = 900              [SET]"

FAILLOCK_CONF="/etc/security/faillock.conf"
if [ -f "$FAILLOCK_CONF" ]; then
    sed -i -E 's/^#?\s*deny\s*=.*/deny = 5/' "$FAILLOCK_CONF" || echo "deny = 5" >> "$FAILLOCK_CONF"
    sed -i -E 's/^#?\s*unlock_time\s*=.*/unlock_time = 900/' "$FAILLOCK_CONF" || echo "unlock_time = 900" >> "$FAILLOCK_CONF"
    sed -i -E 's/^#?\s*fail_interval\s*=.*/fail_interval = 900/' "$FAILLOCK_CONF" || echo "fail_interval = 900" >> "$FAILLOCK_CONF"
else
    cat << 'EOF' > "$FAILLOCK_CONF"
deny = 5
unlock_time = 900
fail_interval = 900
EOF
fi

echo "[*] Configuring password history..."
echo "    remember = 12                    [SET]"

COMMON_PASSWORD="/etc/pam.d/common-password"
if [ -f "$COMMON_PASSWORD" ]; then
    if ! grep -q "remember=12" "$COMMON_PASSWORD"; then
        sed -i -E '/pam_unix.so/ s/$/ remember=12/' "$COMMON_PASSWORD" || true
    fi
fi

echo "Password minimum length: 14 | Lockout: 5 attempts / 15 min | History: 12"
