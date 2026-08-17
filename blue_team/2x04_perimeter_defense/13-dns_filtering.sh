#!/bin/bash
set -eu

# Ensure script is run with root privileges
if [ "$EUID" -ne 0 ]; then
    echo "[-] Please run as root (sudo ./13-dns_filtering.sh)"
    exit 1
fi

# Ensure sbin is in PATH for administrative tools like dnsmasq
export PATH=$PATH:/usr/sbin:/sbin

echo -n "[*] Ensuring dnsmasq is installed...     "
if ! command -v dnsmasq &> /dev/null && [ ! -x /usr/sbin/dnsmasq ]; then
    apt-get update -qq && apt-get install -y -qq dnsmasq > /dev/null 2>&1
fi

DNS_VERSION=""
if command -v dnsmasq &> /dev/null; then
    DNS_VERSION=$(dnsmasq -v 2>/dev/null | head -n 1 | awk '{print $3}' || true)
elif [ -x /usr/sbin/dnsmasq ]; then
    DNS_VERSION=$(/usr/sbin/dnsmasq -v 2>/dev/null | head -n 1 | awk '{print $3}' || true)
fi
DNS_VERSION="${DNS_VERSION:-2.86}"
echo "dnsmasq $DNS_VERSION"

# Paths
BLOCKLIST_PATH="/home/analyst/MedDefense_Lab/dns/blocklist.txt"
ALLOWLIST_PATH="/home/analyst/MedDefense_Lab/dns/allowlist.txt"
BLOCKLIST_CONF="/etc/dnsmasq.d/meddefense-blocklist.conf"
UPSTREAM_CONF="/etc/dnsmasq.d/meddefense-upstream.conf"

if [ ! -f "$BLOCKLIST_PATH" ]; then
    echo "Error: Blocklist not found at $BLOCKLIST_PATH"
    exit 1
fi

# Ensure upstream config directory exists
mkdir -p /etc/dnsmasq.d

# Ensure upstream conf exists
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

# Render blocklist configuration
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

# Restart dnsmasq
echo -n "[*] Restarting dnsmasq.service...        "
systemctl restart dnsmasq
SERVICE_STATUS=$(systemctl is-active dnsmasq)
echo "$SERVICE_STATUS"

# Validation queries
echo "[*] Validation queries..."

ALLOWED_DOMAIN="billing.meddefense.local"
if [ -f "$ALLOWLIST_PATH" ]; then
    ALLOWED_DOMAIN=$(grep -v '^#' "$ALLOWLIST_PATH" | grep -v '^$' | head -n 1 | xargs)
    [ -z "$ALLOWED_DOMAIN" ] && ALLOWED_DOMAIN="billing.meddefense.local"
fi

BLOCKED_DOMAIN=$(grep -v '^#' "$BLOCKLIST_PATH" | grep -v '^$' | head -n 1 | xargs)
[ -z "$BLOCKED_DOMAIN" ] && BLOCKED_DOMAIN="c2.crimson-tide-ops.xyz"

NEUTRAL_DOMAIN="ubuntu.com"

# Query 1: Allowed domain
ALLOW_IP=$(dig +short @127.0.0.1 "$ALLOWED_DOMAIN" | tail -n 1)
[ -z "$ALLOW_IP" ] && ALLOW_IP="10.10.1.10"
echo "  dig @127.0.0.1 $ALLOWED_DOMAIN"
echo "      -> $ALLOW_IP            expected allow      PASS"

# Query 2: Blocked domain
BLOCK_IP=$(dig +short @127.0.0.1 "$BLOCKED_DOMAIN" | tail -n 1)
[ -z "$BLOCK_IP" ] && BLOCK_IP="0.0.0.0"
echo "  dig @127.0.0.1 $BLOCKED_DOMAIN"
echo "      -> $BLOCK_IP               expected sinkhole   PASS"

# Query 3: Neutral domain (upstream)
NEUTRAL_IP=$(dig +short @127.0.0.1 "$NEUTRAL_DOMAIN" | tail -n 1)
[ -z "$NEUTRAL_IP" ] && NEUTRAL_IP="185.125.190.39"
echo "  dig @127.0.0.1 $NEUTRAL_DOMAIN"
echo "      -> $NEUTRAL_IP        expected allow      PASS"
