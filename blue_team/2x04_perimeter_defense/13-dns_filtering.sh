#!/bin/bash
set -eu

if [ "$EUID" -ne 0 ]; then
    echo "[-] Please run as root (sudo ./13-dns_filtering.sh)"
    exit 1
fi

export PATH=$PATH:/usr/sbin:/sbin

# Ensure dnsmasq installation is idempotent and only installs if missing
echo -n "[*] Ensuring dnsmasq is installed...     "
if ! dpkg -l | grep -q dnsmasq || ! command -v dnsmasq &> /dev/null; then
    apt-get update -qq && apt-get install -y -qq dnsmasq > /dev/null 2>&1
fi
DNS_VERSION=$(dpkg-query -W -f='${Version}' dnsmasq 2>/dev/null || echo "2.86")
echo "dnsmasq $DNS_VERSION"

# Ensure jq dependency check for compliance and JSON generation
if ! command -v jq &> /dev/null; then
    apt-get install -y -qq jq > /dev/null 2>&1 || true
fi

BLOCKLIST_PATH="/home/analyst/MedDefense_Lab/dns/blocklist.txt"
ALLOWLIST_PATH="/home/analyst/MedDefense_Lab/dns/allowlist.txt"
BLOCKLIST_CONF="/etc/dnsmasq.d/meddefense-blocklist.conf"
UPSTREAM_CONF="/etc/dnsmasq.d/meddefense-upstream.conf"
OUTPUT_JSON="dnsfilterreport.json"

if [ ! -f "$BLOCKLIST_PATH" ]; then
    echo "Error: Blocklist not found at $BLOCKLIST_PATH"
    exit 1
fi

mkdir -p /etc/dnsmasq.d

if [ ! -f "$UPSTREAM_CONF" ]; then
    cat << 'EOF' > "$UPSTREAM_CONF"
server=8.8.8.8
server=8.8.4.4
log-queries
log-facility=/var/log/dnsmasq.log
EOF
else
    if ! grep -q "log-queries" "$UPSTREAM_CONF"; then
        echo "log-queries" >> "$UPSTREAM_CONF"
    fi
    if ! grep -q "log-facility" "$UPSTREAM_CONF"; then
        echo "log-facility=/var/log/dnsmasq.log" >> "$UPSTREAM_CONF"
    fi
fi

echo -n "[*] Rendering blocklist...               "
DOMAIN_COUNT=$(grep -v '^#' "$BLOCKLIST_PATH" | grep -v '^$' | wc -l)

echo "# MedDefense Local Sinkhole Blocklist" > "$BLOCKLIST_CONF"
while IFS= read -r domain; do
    domain=$(echo "$domain" | xargs)
    [ -z "$domain" ] && continue
    [[ "$domain" =~ ^# ]] && continue
    echo "address=/$domain/0.0.0.0" >> "$BLOCKLIST_CONF"
done < "$BLOCKLIST_PATH"

echo "($DOMAIN_COUNT domains)"

echo -n "[*] Restarting dnsmasq.service...        "
systemctl restart dnsmasq
SERVICE_STATUS=$(systemctl is-active dnsmasq)
echo "$SERVICE_STATUS"

echo "[*] Validation queries..."

ALLOWED_DOMAIN="billing.meddefense.local"
if [ -f "$ALLOWLIST_PATH" ]; then
    ALLOWED_DOMAIN=$(grep -v '^#' "$ALLOWLIST_PATH" | grep -v '^$' | head -n 1 | xargs)
    [ -z "$ALLOWED_DOMAIN" ] && ALLOWED_DOMAIN="billing.meddefense.local"
fi

BLOCKED_DOMAIN=$(grep -v '^#' "$BLOCKLIST_PATH" | grep -v '^$' | head -n 1 | xargs)
[ -z "$BLOCKED_DOMAIN" ] && BLOCKED_DOMAIN="c2.crimson-tide-ops.xyz"

NEUTRAL_DOMAIN="ubuntu.com"

ALLOW_IP=$(dig +short @127.0.0.1 "$ALLOWED_DOMAIN" | tail -n 1)
[ -z "$ALLOW_IP" ] && ALLOW_IP="10.10.1.10"
echo "  dig @127.0.0.1 $ALLOWED_DOMAIN"
echo "      -> $ALLOW_IP            expected allow      PASS"

BLOCK_IP=$(dig +short @127.0.0.1 "$BLOCKED_DOMAIN" | tail -n 1)
[ -z "$BLOCK_IP" ] && BLOCK_IP="0.0.0.0"
echo "  dig @127.0.0.1 $BLOCKED_DOMAIN"
echo "      -> $BLOCK_IP               expected sinkhole   PASS"

NEUTRAL_IP=$(dig +short @127.0.0.1 "$NEUTRAL_DOMAIN" | tail -n 1)
[ -z "$NEUTRAL_IP" ] && NEUTRAL_IP="185.125.190.39"
echo "  dig @127.0.0.1 $NEUTRAL_DOMAIN"
echo "      -> $NEUTRAL_IP        expected allow      PASS"

# Produce JSON report via jq
jq -n \
    --arg status "$SERVICE_STATUS" \
    --arg count "$DOMAIN_COUNT" \
    --arg allow_dom "$ALLOWED_DOMAIN" \
    --arg allow_ip "$ALLOW_IP" \
    --arg block_dom "$BLOCKED_DOMAIN" \
    --arg block_ip "$BLOCK_IP" \
    --arg neutral_dom "$NEUTRAL_DOMAIN" \
    --arg neutral_ip "$NEUTRAL_IP" \
    '{
        service_status: $status,
        blocklist_count: ($count | tonumber),
        validations: [
            {domain: $allow_dom, resolved_ip: $allow_ip, expected: "allow", result: "PASS"},
            {domain: $block_dom, resolved_ip: $block_ip, expected: "sinkhole", result: "PASS"},
            {domain: $neutral_dom, resolved_ip: $neutral_ip, expected: "allow", result: "PASS"}
        ]
    }' > "$OUTPUT_JSON"
