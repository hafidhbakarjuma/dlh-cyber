#!/bin/bash
set -euo pipefail

EVIDENCE_ROOT="${1:-$HOME/evidence_pack_primary}"
MANIFEST_FILE="source_inventory.json"

if [ ! -d "$EVIDENCE_ROOT" ]; then
    echo "Error: Evidence root directory $EVIDENCE_ROOT does not exist." >&2
    exit 1
fi

echo "Scanning evidence pack at: $EVIDENCE_ROOT"

cat << EOF > "$MANIFEST_FILE"
{
  "scanned_at": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "evidence_root": "$EVIDENCE_ROOT",
  "sources": [
EOF

first_entry=true

# Find all files recursively in the evidence pack
while IFS= read -r file; do
    [ -f "$file" ] || continue
    rel_path="${file#$EVIDENCE_ROOT/}"
    
    # Skip non-evidence root files like MANIFEST.sha256 or README.txt if needed, 
    # but ensure standard subfolders are fully scanned.
    top_dir=$(echo "$rel_path" | cut -d'/' -f1)

    size_bytes=$(stat -f%z "$file" 2>/dev/null || stat -c%s "$file" 2>/dev/null)
    sha256=$(sha256sum "$file" | awk '{print $1}')
    line_count=$(wc -l < "$file" 2>/dev/null || echo 0)

    # Determine source_type and whether it uses line_count or record_count
    source_type="unknown"
    is_text_log=false

    if [[ "$top_dir" == "linux" ]]; then
        source_type="linux_text"
        is_text_log=true
    elif [[ "$top_dir" == "windows" ]]; then
        source_type="windows_json"
    elif [[ "$top_dir" == "network" ]]; then
        if [[ "$file" == *.csv ]]; then
            source_type="network_csv"
        else
            source_type="network_json"
        fi
    elif [[ "$top_dir" == "context" ]]; then
        source_type="context_json"
    elif [[ "$top_dir" == "student_telemetry" ]]; then
        source_type="windows_json"
    fi

    # Extract timestamps using a robust python helper, formatting as JSON null if missing
    timestamps=$(python3 -c '
import sys, re, json
filepath = sys.argv[1]
first_ts, last_ts = None, None
iso_regex = re.compile(r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b")
try:
    with open(filepath, "r", errors="ignore") as f:
        for line in f:
            if line.strip().startswith("{"):
                try:
                    data = json.loads(line)
                    for k in ["@timestamp", "Timestamp", "time", "event_time", "datetime", "timestamp"]:
                        if k in data and isinstance(data[k], str):
                            if not first_ts: first_ts = data[k]
                            last_ts = data[k]
                            break
                except:
                    pass
            matches = iso_regex.findall(line)
            if matches:
                if not first_ts: first_ts = matches[0]
                last_ts = matches[-1]
except:
    pass

f_out = f"\"{first_ts}\"" if first_ts else "null"
l_out = f"\"{last_ts}\"" if last_ts else "null"
print(f"{f_out}|{l_out}")
' "$file" 2>/dev/null || echo "null|null")

    f_time=$(echo "$timestamps" | cut -d'|' -f1)
    l_time=$(echo "$timestamps" | cut -d'|' -f2)
    parse_status="ok"

    if [ "$first_entry" = true ]; then
        first_entry=false
    else
        echo "," >> "$MANIFEST_FILE"
    fi

    # Write JSON object matching precise keys and types
    if [ "$is_text_log" = true ]; then
        cat << EOF >> "$MANIFEST_FILE"
    {
      "path": "$rel_path",
      "source_type": "$source_type",
      "size_bytes": $size_bytes,
      "sha256": "$sha256",
      "line_count": $line_count,
      "first_event_time": $f_time,
      "last_event_time": $l_time,
      "parse_status": "$parse_status"
    }
EOF
    else
        cat << EOF >> "$MANIFEST_FILE"
    {
      "path": "$rel_path",
      "source_type": "$source_type",
      "size_bytes": $size_bytes,
      "sha256": "$sha256",
      "record_count": $line_count,
      "first_event_time": $f_time,
      "last_event_time": $l_time,
      "parse_status": "$parse_status"
    }
EOF
    fi

done < <(find "$EVIDENCE_ROOT" -type f ! -name "MANIFEST.sha256" ! -name "README.txt" | sort)

echo "" >> "$MANIFEST_FILE"
echo "  ]" >> "$MANIFEST_FILE"
echo "}" >> "$MANIFEST_FILE"

echo "manifest written to $MANIFEST_FILE"
