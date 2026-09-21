#!/bin/bash
# ==============================================================================
# Script Name: 1-phishing_click.sh
# Description: Analyzes the phishing click PCAP for DNS, TLS, and exchange metadata.
# Usage: ./1-phishing_click.sh <phishing_click.pcap>
# ==============================================================================

set -euo pipefail

PCAP_FILE="${1:-phishing_click.pcap}"

if [ ! -f "$PCAP_FILE" ]; then
    echo "Error: PCAP file '$PCAP_FILE' not found." >&2
    exit 1
fi

echo "[*] Analyzing phishing click capture: $PCAP_FILE"
echo ""

echo "=== DNS RESOLUTION ==="
# Filter for DNS queries and responses involving meddefense-portal.com
tshark -r "$PCAP_FILE" -Y "dns.qry.name == \"meddefense-portal.com\"" -T fields \
    -e frame.time_relative -e dns.qry.name -e dns.a -e dns.resp.ttl -e ip.src -e ip.dst 2>/dev/null || true

echo ""
echo "=== TLS HANDSHAKE ==="
# Extract ClientHello SNI, version, and ciphers
echo "--- Client Hello ---"
tshark -r "$PCAP_FILE" -Y "tls.handshake.type == 1" -T fields \
    -e frame.time_relative -e ip.src -e ip.dst \
    -e tls.handshake.extension_server_name \
    -e tls.handshake.version \
    -e tls.handshake.ciphersuite 2>/dev/null || true

echo ""
echo "--- Server Certificate Metadata ---"
tshark -r "$PCAP_FILE" -Y "tls.handshake.type == 11" -T fields \
    -e frame.time_relative -e x509sat.uTF8String -e x509ce.subject -e x509ce.issuer 2>/dev/null || true

echo ""
echo "=== DATA EXCHANGE SUMMARY ==="
# Show conversation breakdown between the nurse workstation and the phishing IP
tshark -r "$PCAP_FILE" -q -z conv,ip

echo ""
echo "=== POST-CLICK DNS ACTIVITY ==="
# Check for queries to the legitimate domain right after
tshark -r "$PCAP_FILE" -Y "dns.qry.name == \"meddefense.com\"" -T fields \
    -e frame.time_relative -e dns.qry.name -e dns.a 2>/dev/null || true

echo "[*] Task 1 analysis script execution completed."
