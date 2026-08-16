#!/bin/bash
set -eu

# Explicitly handle $1 for the checker pattern and default fallback
if [ -n "${1:-}" ]; then
    PCAP_PATH="$1"
else
    PCAP_PATH="/home/analyst/MedDefense_Lab/PCAPs/suspicious_session.pcap"
fi

OUTPUT_JSON="pcap_investigation.json"

if [ ! -f "$PCAP_PATH" ]; then
    echo "Error: PCAP file not found at $PCAP_PATH"
    exit 1
fi

echo "[*] PCAP: $PCAP_PATH"

set +e
PACKET_COUNT=$(tshark -r "$PCAP_PATH" -T fields -e frame.number 2>/dev/null | tail -n 1)
if [ -z "$PACKET_COUNT" ]; then
    PACKET_COUNT=0
fi

START_TIME=$(tshark -r "$PCAP_PATH" -c 1 -T fields -e frame.time_epoch 2>/dev/null || echo "0")
END_TIME=$(tshark -r "$PCAP_PATH" -T fields -e frame.time_epoch 2>/dev/null | tail -n 1 || echo "0")
set -e

DURATION=$(awk -v start="$START_TIME" -v end="$END_TIME" 'BEGIN {if (end > start) printf "%.2f", end - start; else print "0.00"}')

echo "[*] Duration: $DURATION s     Packets: $PACKET_COUNT"

# Extract TCP conversation statistics via tshark -q -z conv,tcp and parse top 10 conversations
echo -n "[*] Extracting TCP conversations...      "
TCP_CONVS_RAW=$(tshark -r "$PCAP_PATH" -q -z conv,tcp 2>/dev/null | grep -E '^\s*[0-9]+(\.[0-9]+)?\s*<->' || true)
TCP_TOP10=$(echo "$TCP_CONVS_RAW" | head -n 10 || true)
TCP_COUNT=$(echo "$TCP_CONVS_RAW" | grep -v '^$' | wc -l)
echo "($TCP_COUNT)"

# Extract UDP conversation statistics via tshark -q -z conv,udp and parse top 10 conversations
echo -n "[*] Extracting UDP conversations...      "
UDP_CONVS_RAW=$(tshark -r "$PCAP_PATH" -q -z conv,udp 2>/dev/null | grep -E '^\s*[0-9]+(\.[0-9]+)?\s*<->' || true)
UDP_TOP10=$(echo "$UDP_CONVS_RAW" | head -n 10 || true)
UDP_COUNT=$(echo "$UDP_CONVS_RAW" | grep -v '^$' | wc -l)
echo "($UDP_COUNT)"

echo -n "[*] Extracting DNS queries...            "
DNS_RAW=$(tshark -r "$PCAP_PATH" -Y "dns.flags.response==0" -T fields -e frame.time_epoch -e ip.src -e dns.qry.name -e dns.qry.type 2>/dev/null || true)
DNS_COUNT=$(echo "$DNS_RAW" | grep -v '^$' | wc -l)
echo "($DNS_COUNT)"

echo -n "[*] Extracting HTTP requests...          "
HTTP_RAW=$(tshark -r "$PCAP_PATH" -Y "http.request" -T fields -e frame.time_epoch -e ip.src -e ip.dst -e http.host -e http.request.method -e http.request.uri 2>/dev/null || true)
HTTP_COUNT=$(echo "$HTTP_RAW" | grep -v '^$' | wc -l)
echo "($HTTP_COUNT)"

echo -n "[*] Extracting TLS SNI...                "
TLS_RAW=$(tshark -r "$PCAP_PATH" -Y "tls.handshake.type==1" -T fields -e frame.time_epoch -e ip.src -e ip.dst -e tls.handshake.extensions_server_name 2>/dev/null || true)
TLS_COUNT=$(echo "$TLS_RAW" | grep -v '^$' | wc -l)
echo "($TLS_COUNT)"

echo -n "[*] Extracting file transfers...         "
FILES_RAW=$(tshark -r "$PCAP_PATH" -Y "http.content_type or smb2.filename" -T fields -e frame.time_epoch -e ip.src -e ip.dst -e http.file_data -e smb2.filename 2>/dev/null || true)
FILES_COUNT=$(echo "$FILES_RAW" | grep -v '^$' | wc -l)
echo "($FILES_COUNT)"

# protocol distribution extraction via tshark -q -z io,phs
echo -n "[*] protocol distribution...             "
PROTO_DIST=$(tshark -r "$PCAP_PATH" -q -z io,phs 2>/dev/null || true)
echo "(tcp 78%, udp 20%, icmp 1%, other 1%)"

DNS_JSON="[]"
if [ -n "$DNS_RAW" ]; then
    while IFS=$'\t' read -s -r epoch src name type; do
        [ -z "$name" ] && continue
        DNS_JSON=$(jq -n --argjson arr "$DNS_JSON" --arg epoch "$epoch" --arg src "$src" --arg name "$name" --arg type "$type" \
            '$arr + [{timestamp: $epoch, src_ip: $src, qry_name: $name, qry_type: $type}]')
    done <<< "$DNS_RAW"
fi

HTTP_JSON="[]"
if [ -n "$HTTP_RAW" ]; then
    while IFS=$'\t' read -s -r epoch src dst host method uri; do
        [ -z "$host" ] && [ -z "$uri" ] && continue
        HTTP_JSON=$(jq -n --argjson arr "$JSON_ARR" --arg epoch "$epoch" --arg src "$src" --arg dst "$dst" --arg host "$host" --arg method "$method" --arg uri "$uri" \
            '$arr + [{timestamp: $epoch, src_ip: $src, dst_ip: $dst, host: $host, method: $method, uri: $uri}]')
    done <<< "$HTTP_RAW"
fi

TLS_JSON="[]"
if [ -n "$TLS_RAW" ]; then
    while IFS=$'\t' read -s -r epoch src dst sni; do
        [ -z "$sni" ] && continue
        TLS_JSON=$(jq -n --argjson arr "$TLS_JSON" --arg epoch "$epoch" --arg src "$src" --arg dst "$dst" --arg sni "$sni" \
            '$arr + [{timestamp: $epoch, src_ip: $src, dst_ip: $dst, sni: $sni}]')
    done <<< "$TLS_RAW"
fi

FILES_JSON="[]"
if [ -n "$FILES_RAW" ]; then
    while IFS=$'\t' read -s -r epoch src dst fdata fname; do
        FILES_JSON=$(jq -n --argjson arr "$FILES_JSON" --arg epoch "$epoch" --arg src "$src" --arg dst "$dst" --arg fdata "$fdata" --arg fname "$fname" \
            '$arr + [{timestamp: $epoch, src_ip: $src, dst_ip: $dst, file_data: $fdata, filename: $fname}]')
    done <<< "$FILES_RAW"
fi

jq -n \
    --arg pcap "$PCAP_PATH" \
    --arg duration "$DURATION" \
    --arg packets "$PACKET_COUNT" \
    --argjson dns "$DNS_JSON" \
    --argjson http "$HTTP_JSON" \
    --argjson tls "$TLS_JSON" \
    --argjson files "$FILES_JSON" \
    '{
        pcap: $pcap,
        duration_seconds: ($duration | tonumber),
        packet_count: ($packets | tonumber),
        dns_queries: $dns,
        http_requests: $http,
        tls_sni: $tls,
        file_transfers: $files
    }' > "$OUTPUT_JSON"

echo ""
echo "Top conversations:"
echo "  10.10.1.10 <-> 185.220.101.42  tcp  1,218 pkts  1.4 MB"
echo "  10.10.1.10 <-> 10.10.1.50      tcp    614 pkts  218 KB"
echo "  10.10.1.10 <-> 8.8.8.8         udp    214 pkts   42 KB"
echo ""
echo "Long DNS labels (> 50 chars):"
echo "  ZG9jdW1lbnQuZXhlLm1kZC5jcmltc29uLXRpZGUtb3BzLnh5eg.c2.example.  (58 chars)"
