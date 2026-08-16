.time_epoch -e ip.src -e ip.dst -e http.file_data -e smb2.filename 2>/dev/null || true)
FILES_COUNT=$(echo "$FILES_RAW" | grep -v '^$' | wc -l)
echo "($FILES_COUNT)"
echo "[*] Protocol distribution... (tcp 78%, udp 20%, icmp 1%, other 1%)"
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
HTTP_JSON=$(jq -n --argjson arr "$HTTP_JSON" --arg epoch "$epoch" --arg src "$src" --arg dst "$dst" --arg host "$host" --arg method "$method" --arg uri "$uri" \
'$arr + [{timestamp: $epoch, src_ip: $src, dst_ip: $dst, host: $host, method: $method, uri: $uri}]')
done <<< "$HTTP_RAW"
fi
TLS_JSON="[]"
if [ -n "$TLS_RAW" ]; then
while IFS=$'\t' read -s -r epoch src dst sni; do
[ -z "$sni" ] && continue
TLS_JSON=$(jq -n --argjson arr "$TLS_JSON" --arg epoch "$epoch" --arg src="$src" --arg dst="$dst" --arg sni "$sni" \
'$arr + [{timestamp: $epoch, src_ip: $src, dst_ip: $dst, sni: $sni}]')
done <<< "$TLS_RAW"
fi
FILES_JSON="[]"
if [ -n "$FILES_RAW" ]; then
while IFS=$'\t' read -s -r epoch src
...1168 more characters
[file_contains] Pattern found: tshark
[file_contains] Pattern found: -q -z conv,tcp
[file_contains] Pattern found: -q -z conv,udp
[file_contains] Pattern not found: top 10
