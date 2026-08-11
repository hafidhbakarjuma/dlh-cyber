#!/bin/bash

# 2-pre_patch_snapshot.sh
# MedDefense - Patch Management
# Task 2: Pre-Patch Snapshot

set -euo pipefail

OUTPUT_FILE="pre_patch_state.json"

# Dependency check
for cmd in dpkg systemctl ss sha256sum jq uname hostname; do
    command -v "$cmd" >/dev/null 2>&1 || { echo "[ERROR] Missing required command: $cmd" >&2; exit 1; }
done

echo "[INFO] Capturing pre-patch system state..."

# 1. Basic Metadata
TIMESTAMP="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
HOSTNAME_VAL="$(hostname)"
KERNEL_VAL="$(uname -r)"
REBOOT_REQUIRED="false"
[ -f /var/run/reboot-required ] && REBOOT_REQUIRED="true"

# 2. Record package versions via dpkg
echo "[INFO] Recording installed package versions..."
PACKAGES_JSON=$(dpkg-query -W -f='${binary:Package}\t${Version}\n' | \
    jq -R -s '
        [
            split("\n")[]
            | select(length > 0)
            | split("\t")
            | {package: .[0], version: .[1]}
        ]
    ')

# 3. Record service states for active systemd services
echo "[INFO] Recording active systemd service states..."
SERVICES_JSON="[]"
while read -r service_name; do
    [ -z "$service_name" ] && continue

    active_state=$(systemctl show -p ActiveState --value "$service_name" 2>/dev/null || echo "unknown")
    sub_state=$(systemctl show -p SubState --value "$service_name" 2>/dev/null || echo "unknown")
    main_pid=$(systemctl show -p MainPID --value "$service_name" 2>/dev/null || echo "0")

    service_obj=$(jq -n \
        --arg svc "$service_name" \
        --arg act "$active_state" \
        --arg sub "$sub_state" \
        --arg pid "$main_pid" \
        '{service: $svc, active_state: $act, sub_state: $sub, main_pid: ($pid | tonumber)}')

    SERVICES_JSON=$(echo "$SERVICES_JSON" | jq --argjson obj "$service_obj" '. + [$obj]')
done < <(systemctl list-units --type=service --state=active --no-legend --no-pager | awk '{print $1}')

# 4. Record listening sockets via ss -tulnp
echo "[INFO] Recording listening sockets..."
LISTENING_JSON=$(ss -tulnp 2>/dev/null | awk 'NR>1 {print}' | jq -R -s '
    [
        split("\n")[]
        | select(length > 0)
        | {socket_info: .}
    ]
')

# 5. Record SHA-256 hashes of /etc configuration files tracked by dpkg
echo "[INFO] Calculating SHA-256 hashes of package-tracked configuration files under /etc..."
CONFFILES_JSON="{}"

# Extract conffiles tracked by dpkg: format is " /etc/path package"
while read -r line; do
    [ -z "$line" ] && continue
    # dpkg -S or dpkg status parsing for conffiles. Alternatively, query package status files.
    # A reliable way to get tracked conffiles under /etc is via dpkg-query:
    # Let's collect files from dpkg-query conffiles list:
    # Format: package: /etc/file
    true
done < <(dpkg-query -W -f='${Conffiles}\n' 2>/dev/null)

# Safer loop using dpkg-query for conffiles
conffile_map=$(mktemp)
dpkg-query -W -f='${Package}\n${Conffiles}\n' 2>/dev/null | awk '
    NF == 1 { pkg = $1; next }
    NF >= 2 { print $1 }
' | while read -r cfile; do
    if [ -f "$cfile" ]; then
        hash=$(sha256sum "$cfile" 2>/dev/null | awk '{print $1}')
        if [ -n "$hash" ]; then
            echo "$cfile:$hash"
        fi
    fi
done > "$conffile_map"

CONFFILES_JSON=$(jq -n --argfile map <(awk -F: '{printf "\"%s\": \"%s\",", $1, $2}' "$conffile_map" | sed 's/,$//' | awk '{print "{" $0 "}"}') '$map')
rm -f "$conffile_map"

# Fallback if empty
if [ -z "$CONFFILES_JSON" ] || [ "$CONFFILES_JSON" = "null" ]; then
    CONFFILES_JSON="{}"
fi

# Count metadata summaries for the expected output convenience/schema validation
pkg_count=$(echo "$PACKAGES_JSON" | jq 'length')
svc_count=$(echo "$SERVICES_JSON" | jq 'length')

# 6. Emit pre_patch_state.json
echo "[INFO] Generating $OUTPUT_FILE..."
jq -n \
    --arg timestamp "$TIMESTAMP" \
    --arg hostname "$HOSTNAME_VAL" \
    --arg kernel "$KERNEL_VAL" \
    --argjson packages_count "$pkg_count" \
    --argjson packages_list "$PACKAGES_JSON" \
    --argjson services_count "$svc_count" \
    --argjson services_list "$SERVICES_JSON" \
    --argjson listening "$LISTENING_JSON" \
    --argjson conffile_hashes "$CONFFILES_JSON" \
    --argjson reboot_required "$REBOOT_REQUIRED" \
    '{
        timestamp: $timestamp,
        hostname: $hostname,
        kernel: $kernel,
        packages: $packages_count,
        packages_detail: $packages_list,
        services: $services_count,
        services_detail: $services_list,
        listening: $listening,
        conffile_hashes: $conffile_hashes,
        reboot_required: $reboot_required
    }' > "$OUTPUT_FILE"

FILE_SIZE=$(du -h "$OUTPUT_FILE" | awk '{print $1}')

echo "Snapshot: $OUTPUT_FILE"
echo "Size: $FILE_SIZE"
echo "Kernel: $KERNEL_VAL"
echo "Reboot required: $REBOOT_REQUIRED"
