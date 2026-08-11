#!/bin/bash
set -euo pipefail

CRITICALITY_FILE="service_criticality.json"
OUTPUT_FILE="service_dependency_map.json"

# Temporary file to build the JSON array safely
TEMP_JSON=$(mktemp)
echo "[" > "$TEMP_JSON"
first=true

# Iterate over active systemd service units
while read -r service _; do
    [ -z "$service" ] && continue

    # 1. Resolve Executable Path from MainPID or ExecStart
    exec_path=""
    main_pid=$(systemctl show -p MainPID --value "$service" 2>/dev/null || echo "0")
    if [ "$main_pid" -gt 0 ] && [ -e "/proc/$main_pid/exe" ]; then
        exec_path=$(readlink -f "/proc/$main_pid/exe" 2>/dev/null || true)
    fi

    if [ -z "$exec_path" ] || [ ! -e "$exec_path" ]; then
        exec_path=$(systemctl show -p ExecStart --property=path --value "$service" 2>/dev/null || true)
        if [ -z "$exec_path" ] || [ ! -e "$exec_path" ]; then
            exec_start=$(systemctl show -p ExecStart --value "$service" 2>/dev/null || true)
            exec_path=$(echo "$exec_start" | awk '{print $1}' | tr -d '"()')
        fi
    fi

    # Skip if no valid absolute path to an executable is found
    [[ "$exec_path" != /* ]] || [ ! -e "$exec_path" ] && continue

    # 2. Resolve owning package for the main executable
    owning_package=$(dpkg -S "$exec_path" 2>/dev/null | head -n1 | cut -d: -f1 || echo "")

    # 3. Collect linked packages including the owning package and shared libraries via ldd
    linked_pkgs=()
    if [ -n "$owning_package" ]; then
        linked_pkgs+=("$owning_package")
    fi

    if file "$exec_path" 2>/dev/null | grep -q "ELF"; then
        while read -r lib_path; do
            if [ -n "$lib_path" ] && [ -e "$lib_path" ]; then
                pkg=$(dpkg -S "$lib_path" 2>/dev/null | head -n1 | cut -d: -f1 || echo "")
                if [ -n "$pkg" ]; then
                    linked_pkgs+=("$pkg")
                fi
            fi
        done < <(ldd "$exec_path" 2>/dev/null | grep "=>" | awk '{print $3}' | grep "^/")
    fi

    # Deduplicate and sort packages
    mapfile -t unique_pkgs < <(printf '%s\n' "${linked_pkgs[@]}" | sort -u)

    # 4. Resolve criticality label (defaults to "low" if not specified)
    criticality="low"
    if [ -f "$CRITICALITY_FILE" ]; then
        crit_val=$(jq -r --arg s "$service" '.[$s] // "low"' "$CRITICALITY_FILE" 2>/dev/null || echo "low")
        [ -n "$crit_val" ] && [ "$crit_val" != "null" ] && criticality="$crit_val"
    fi

    # 5. Build JSON object for the service
    json_obj=$(jq -n \
        --arg svc "$service" \
        --arg epath "$exec_path" \
        --arg opkg "$owning_package" \
        --arg crit "$criticality" \
        --argjson pkgs "$(printf '%s\n' "${unique_pkgs[@]}" | jq -R . | jq -s .)" \
        '{
            service: $svc,
            exec_path: $epath,
            owning_package: $opkg,
            linked_packages: $pkgs,
            criticality: $crit,
            restart_required_on_patch: true
        }')

    if [ "$first" = true ]; then
        echo "$json_obj" >> "$TEMP_JSON"
        first=false
    else
        echo ",$json_obj" >> "$TEMP_JSON"
    fi

done < <(systemctl list-units --type=service --state=active --no-legend --no-pager)

echo "]" >> "$TEMP_JSON"
mv "$TEMP_JSON" "$OUTPUT_FILE"
echo "Successfully generated $OUTPUT_FILE"
