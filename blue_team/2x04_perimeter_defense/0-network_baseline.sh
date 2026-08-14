#!/bin/bash

set -euo pipefail

# ---------------------------------------------------------------------------
# MedDefense - T0 Network Baseline
#
# Purpose:
#   Capture the network state of the hardened endpoint before network
#   security controls are modified.
#
# Output:
#   network_baseline.json
#
# Requirements:
#   - ip
#   - ss
#   - jq
# ---------------------------------------------------------------------------

OUTPUT_FILE="network_baseline.json"
TMP_DIR="$(mktemp -d)"

cleanup() {
    rm -rf "$TMP_DIR"
}

trap cleanup EXIT

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

log() {
    printf '[INFO] %s\n' "$*"
}

error() {
    printf '[ERROR] %s\n' "$*" >&2
}

# ---------------------------------------------------------------------------
# Dependency checks
# ---------------------------------------------------------------------------

require_command() {
    local command_name="$1"

    if ! command -v "$command_name" >/dev/null 2>&1; then
        error "Required command not found: $command_name"
        exit 1
    fi
}

require_command ip
require_command ss
require_command jq
require_command hostname

# ---------------------------------------------------------------------------
# Privilege check
#
# ss -p may require root privileges to resolve processes/PIDs for all
# sockets. T0 explicitly requires socket ownership information.
# ---------------------------------------------------------------------------

if [[ "$EUID" -ne 0 ]]; then
    error "Run this script as root so socket ownership/PID information is available."
    error "Example: sudo ./0-network_baseline.sh"
    exit 1
fi

# ---------------------------------------------------------------------------
# Timestamp / hostname
# ---------------------------------------------------------------------------

timestamp="$(date --iso-8601=seconds)"
hostname_value="$(hostname)"

log "Collecting network baseline for: $hostname_value"
log "Timestamp: $timestamp"

# ---------------------------------------------------------------------------
# 1. Network interfaces
#
# Required source:
#   ip -j addr show
#
# Retain:
#   - interface name
#   - MAC address
#   - link state
#   - assigned addresses
# ---------------------------------------------------------------------------

log "Collecting network interfaces..."

ip -j addr show > "$TMP_DIR/interfaces.json"

interfaces="$(
    jq '
        [
            .[]
            | {
                name: .ifname,
                mac: (.address // null),
                link_state: (.operstate // null),
                addresses: [
                    .addr_info[]?
                    | {
                        family: .family,
                        address: .local,
                        prefix_length: .prefixlen,
                        scope: (.scope // null)
                    }
                ]
            }
        ]
    ' "$TMP_DIR/interfaces.json"
)"

# ---------------------------------------------------------------------------
# 2. Routing table
#
# Required source:
#   ip -j route show
#
# This includes the default gateway when present.
# ---------------------------------------------------------------------------

log "Collecting routing table..."

ip -j route show > "$TMP_DIR/routes.json"

routes="$(
    jq '
        [
            .[]
            | {
                destination: (.dst // "default"),
                gateway: (.gateway // null),
                device: (.dev // null),
                protocol: (.protocol // null),
                scope: (.scope // null),
                metric: (.metric // null),
                table: (.table // null)
            }
        ]
    ' "$TMP_DIR/routes.json"
)"

# ---------------------------------------------------------------------------
# 3. ARP / neighbor table
#
# Required source:
#   ip -j neigh show
#
# Retain:
#   - IP
#   - MAC
#   - state
# ---------------------------------------------------------------------------

log "Collecting neighbor table..."

ip -j neigh show > "$TMP_DIR/neighbors.json"

neighbors="$(
    jq '
        [
            .[]
            | {
                ip: .dst,
                mac: (.lladdr // null),
                state: (
                    if (.state | type) == "array"
                    then .state
                    else [.state // null]
                    end
                ),
                interface: (.dev // null)
            }
        ]
    ' "$TMP_DIR/neighbors.json"
)"

# ---------------------------------------------------------------------------
# Helper: convert ss process information into JSON
#
# Example ss process field:
#
# users:(("sshd",pid=1234,fd=3))
#
# We preserve the raw ownership information and additionally attempt to
# extract process name and PID.
# ---------------------------------------------------------------------------

parse_process() {
    local process_field="$1"

    if [[ -z "$process_field" || "$process_field" == "-" ]]; then
        printf '%s\n' '{"raw":null,"process":null,"pid":null}'
        return
    fi

    local process_name
    local pid

    process_name="$(
        printf '%s\n' "$process_field" |
            sed -n 's/.*users:(("\([^"]*\)".*/\1/p'
    )"

    pid="$(
        printf '%s\n' "$process_field" |
            sed -n 's/.*pid=\([0-9]*\).*/\1/p'
    )"

    jq -n \
        --arg raw "$process_field" \
        --arg process "$process_name" \
        --arg pid "$pid" \
        '{
            raw: $raw,
            process: (if $process == "" then null else $process end),
            pid: (if $pid == "" then null else ($pid | tonumber) end)
        }'
}

# ---------------------------------------------------------------------------
# 4. Listening TCP/UDP sockets
#
# Required source:
#   ss -tulnpH
#
# We use -p so ownership information can be collected.
# ---------------------------------------------------------------------------

log "Collecting listening TCP/UDP sockets..."

ss -tulnpH > "$TMP_DIR/listeners.txt"

listeners_json="$TMP_DIR/listeners.json"

printf '[\n' > "$listeners_json"

first_entry=true

while read -r netid state recv_q send_q local_addr peer_addr process_field; do

    [[ -z "${netid:-}" ]] && continue

    process_json="$(parse_process "${process_field:-}")"

    entry="$(
        jq -n \
            --arg protocol "$netid" \
            --arg state "$state" \
            --arg local "$local_addr" \
            --arg peer "$peer_addr" \
            --argjson process "$process_json" \
            '{
                protocol: $protocol,
                state: $state,
                local_address: $local,
                peer_address: $peer,
                process: $process
            }'
    )"

    if [[ "$first_entry" == true ]]; then
        first_entry=false
    else
        printf ',\n' >> "$listeners_json"
    fi

    printf '%s' "$entry" >> "$listeners_json"

done < "$TMP_DIR/listeners.txt"

printf '\n]\n' >> "$listeners_json"

# ---------------------------------------------------------------------------
# 5. Established outbound connections
#
# Required source:
#   ss -tnpH state established
#
# Retain process ownership information.
# ---------------------------------------------------------------------------

log "Collecting established connections..."

ss -tnpH state established > "$TMP_DIR/established.txt"

established_json="$TMP_DIR/established.json"

printf '[\n' > "$established_json"

first_entry=true

while read -r netid state recv_q send_q local_addr peer_addr process_field; do

    [[ -z "${netid:-}" ]] && continue

    process_json="$(parse_process "${process_field:-}")"

    entry="$(
        jq -n \
            --arg protocol "$netid" \
            --arg state "$state" \
            --arg local "$local_addr" \
            --arg remote "$peer_addr" \
            --argjson process "$process_json" \
            '{
                protocol: $protocol,
                state: $state,
                local_address: $local,
                remote_address: $remote,
                process: $process
            }'
    )"

    if [[ "$first_entry" == true ]]; then
        first_entry=false
    else
        printf ',\n' >> "$established_json"
    fi

    printf '%s' "$entry" >> "$established_json"

done < "$TMP_DIR/established.txt"

printf '\n]\n' >> "$established_json"

# ---------------------------------------------------------------------------
# 6. DNS resolver configuration
#
# Required sources:
#   /etc/resolv.conf
#   resolvectl status --no-pager if systemd-resolved is active
# ---------------------------------------------------------------------------

log "Collecting DNS resolver configuration..."

resolv_conf_json="$(
    jq -Rs '
        split("\n")
        | map(select(length > 0))
    ' /etc/resolv.conf
)"

resolvectl_json='null'

if command -v resolvectl >/dev/null 2>&1; then

    if systemctl is-active --quiet systemd-resolved 2>/dev/null; then
        log "systemd-resolved is active; collecting resolvectl status."

        if resolvectl status --no-pager > "$TMP_DIR/resolvectl.txt" 2>/dev/null; then
            resolvectl_json="$(
                jq -Rs '.' "$TMP_DIR/resolvectl.txt"
            )"
        fi
    fi
fi

dns_resolvers="$(
    jq -n \
        --argjson resolv_conf "$resolv_conf_json" \
        --argjson resolvectl_status "$resolvectl_json" \
        '{
            resolv_conf: $resolv_conf,
            resolvectl_status: $resolvectl_status
        }'
)"

# ---------------------------------------------------------------------------
# 7. Build final JSON artifact
#
# Required top-level keys:
#   timestamp
#   hostname
#   interfaces
#   routes
#   neighbors
#   listening_sockets
#   established_connections
#   dns_resolvers
# ---------------------------------------------------------------------------

log "Building $OUTPUT_FILE..."

jq -n \
    --arg timestamp "$timestamp" \
    --arg hostname "$hostname_value" \
    --argjson interfaces "$interfaces" \
    --argjson routes "$routes" \
    --argjson neighbors "$neighbors" \
    --slurpfile listening_sockets "$listeners_json" \
    --slurpfile established_connections "$established_json" \
    --argjson dns_resolvers "$dns_resolvers" \
    '{
        timestamp: $timestamp,
        hostname: $hostname,
        interfaces: $interfaces,
        routes: $routes,
        neighbors: $neighbors,
        listening_sockets: $listening_sockets[0],
        established_connections: $established_connections[0],
        dns_resolvers: $dns_resolvers
    }' |
    jq '.' > "$OUTPUT_FILE"

# ---------------------------------------------------------------------------
# 8. Validate JSON
# ---------------------------------------------------------------------------

if ! jq empty "$OUTPUT_FILE" >/dev/null 2>&1; then
    error "Generated JSON is invalid."
    exit 1
fi

log "Baseline successfully written to: $OUTPUT_FILE"
log "Interfaces: $(jq '.interfaces | length' "$OUTPUT_FILE")"
log "Routes: $(jq '.routes | length' "$OUTPUT_FILE")"
log "Neighbors: $(jq '.neighbors | length' "$OUTPUT_FILE")"
log "Listening sockets: $(jq '.listening_sockets | length' "$OUTPUT_FILE")"
log "Established connections: $(jq '.established_connections | length' "$OUTPUT_FILE")"

exit 0
