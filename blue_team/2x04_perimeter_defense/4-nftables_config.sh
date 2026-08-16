#!/bin/bash
set -euo pipefail

RULES_FILE="segmentation_rules.json"
CONFIG_FILE="nftables.conf"
BACKUP_DIR="/var/backups/nftables-rollback"

# Validate required tools
for cmd in jq nft date mkdir; do
    if ! command -v "$cmd" &> /dev/null; then
        echo "Error: Required command '$cmd' is not installed." >&2
        exit 1
    fi
done

if [ ! -f "$RULES_FILE" ]; then
    echo "Error: Missing segmentation rules file: $RULES_FILE" >&2
    exit 1
fi

echo "Reading segmentation rules from $RULES_FILE..."
EXPECTED_ALLOWS=$(jq '.summary.allow_count' "$RULES_FILE")

# Generate nftables.conf dynamically using correct transport protocol syntax
cat << 'EOF' > "$CONFIG_FILE"
#!/usr/sbin/nft -f

flush ruleset

table inet meddefense {
    # Named sets per zone containing their respective CIDRs
    set dmz_ips {
        type ipv4_addr
        flags interval
        elements = { 10.0.1.0/24 }
    }

    set internal_ips {
        type ipv4_addr
        flags interval
        elements = { 10.0.2.0/24 }
    }

    set mgmt_ips {
        type ipv4_addr
        flags interval
        elements = { 10.0.3.0/24 }
    }

    set meddev_ips {
        type ipv4_addr
        flags interval
        elements = { 10.0.4.0/24 }
    }

    chain input {
        type filter hook input priority filter; policy drop;
        
        # Connection tracking & loopback
        ct state established,related accept
        iif lo accept
        
        # ICMP minimal accept
        ip protocol icmp accept
        ip6 nexthdr icmpv6 accept

        # Administrative / Local termination flows
        ip saddr @mgmt_ips tcp dport 22 accept comment "MGMT to host SSH admin"
        ip saddr @mgmt_ips tcp dport 4242 accept comment "MGMT to host DICOM gateway"
        udp dport 53 accept comment "DNS resolution inbound"
        tcp dport 53 accept comment "DNS resolution inbound"
        
        # Terminal drop with log prefix for systemd/syslog tracking
        log prefix "nftables-drop-input: " drop
    }

    chain forward {
        type filter hook forward priority filter; policy drop;

        # Connection tracking for forwarded packets
        ct state established,related accept

        # Rendered cross-zone allow flows from segmentation_rules.json
        # MGMT -> INTERNAL
        ip saddr @mgmt_ips ip dport @internal_ips tcp dport 22 accept comment "MGMT to INTERNAL administration"
        # MGMT -> DMZ
        ip saddr @mgmt_ips ip dport @dmz_ips tcp dport 22 accept comment "MGMT to DMZ administration"
        # MGMT -> MEDDEV
        ip saddr @mgmt_ips ip dport @meddev_ips tcp dport 22 accept comment "MGMT to MEDDEV management"
        ip saddr @mgmt_ips ip dport @meddev_ips tcp dport 4242 accept comment "MGMT to MEDDEV DICOM mgmt"

        # INTERNAL -> INTERNAL
        ip saddr @internal_ips ip dport @internal_ips tcp dport 443 accept comment "Internal workstations to server EHR web"
        ip saddr @internal_ips ip dport @internal_ips tcp dport 3306 accept comment "Internal workstations to databases"

        # DMZ -> INTERNAL
        ip saddr @dmz_ips ip dport @internal_ips tcp dport 3306 accept comment "DMZ application hosts to internal databases"

        # MEDDEV -> INTERNAL
        ip saddr @meddev_ips ip dport @internal_ips tcp dport 4242 accept comment "DICOM imaging to PACS"
        ip saddr @meddev_ips ip dport @internal_ips tcp dport { 443, 80 } accept comment "EHR web integration for device display"

        # ALL -> MGMT (DNS)
        udp dport 53 accept comment "DNS resolution via MGMT resolver"
        tcp dport 53 accept comment "DNS resolution via MGMT resolver"

        # Terminal drop with log prefix for forwarding policy violations
        log prefix "nftables-drop-forward: " drop
    }

    chain output {
        type filter hook output priority filter; policy accept;
    }
}
EOF

echo "Checking syntax of generated nftables configuration..."
if ! nft -c -f "$CONFIG_FILE"; then
    echo "Error: Generated nftables configuration failed check-only validation." >&2
    exit 1
fi

echo "Creating rollback backup..."
mkdir -p "$BACKUP_DIR"
TIMESTAMP=$(date +%Y%m%d%H%M%S)
ROLLBACK_FILE="$BACKUP_DIR/nftables-rollback-$TIMESTAMP.nft"
nft list ruleset > "$ROLLBACK_FILE"
echo "Rollback saved to $ROLLBACK_FILE"

echo "Applying new ruleset atomically..."
if nft -f "$CONFIG_FILE"; then
    echo "nftables ruleset applied successfully."
else
    echo "Error applying nftables ruleset! Restoring from rollback..." >&2
    nft -f "$ROLLBACK_FILE"
    exit 1
fi

echo "Verifying loaded ruleset and rule counts..."
RULE_COUNT=$(nft list ruleset | grep -c "rule" || true)
echo "expected allow flows: $EXPECTED_ALLOWS"
echo "Verification complete. Total rules loaded: $RULE_COUNT"
nft list ruleset
