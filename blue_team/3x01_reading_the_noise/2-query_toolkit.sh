#!/bin/bash
set -euo pipefail

# Default HANDOFF_DIR if unset, following project specifications
HANDOFF_DIR="${HANDOFF_DIR:-$HOME/3x00_handoff/evidence_handoff}"
DATA_FILE="$HANDOFF_DIR/data/enriched_events.json"

# Validate that the data file exists
if [ ! -f "$DATA_FILE" ]; then
    echo "Error: Enriched dataset not found at $DATA_FILE" >&2
    echo "Ensure your 3x00 pipeline handoff is in place before running queries." >&2
    exit 1
fi

print_help() {
    cat << EOF
query_toolkit.sh <verb> [options]
  filter     Emit matching records as newline-delimited JSON (ndjson)
  top        Top N values of a field (sorted descending by count)
  distinct   Distinct values of a field (one per line)
  count      Number of matching records (single integer)
  window     Bucketed counts by time window (hour or day)
  help       Display this help message

Options for filtering and projection:
  --source <type>     Filter by log source/type
  --host <h>          Filter by hostname or asset ID
  --category <c>      Filter by event category
  --from <iso>        Filter events starting from ISO timestamp
  --to <iso>          Filter events up to ISO timestamp
  --field <name>      Target field for top, distinct, or window verbs
  --limit <n>         Number of top results to return (default: 10)
  --bucket <hour|day> Time bucket granularity for window verb
EOF
}

if [ $# -eq 0 ] || [ "$1" = "help" ]; then
    print_help
    exit 0
fi

VERB="$1"
shift

# Parse CLI options
SOURCE=""
HOST=""
CATEGORY=""
FROM=""
TO=""
FIELD=""
LIMIT="10"
BUCKET=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --source) SOURCE="$2"; shift 2 ;;
        --host) HOST="$2"; shift 2 ;;
        --category) CATEGORY="$2"; shift 2 ;;
        --from) FROM="$2"; shift 2 ;;
        --to) TO="$2"; shift 2 ;;
        --field) FIELD="$2"; shift 2 ;;
        --limit) LIMIT="$2"; shift 2 ;;
        --bucket) BUCKET="$2"; shift 2 ;;
        *)
            echo "Error: Unknown option $1" >&2
            exit 1
            ;;
    esac
done

# Build resilient jq condition expression covering common schema variations
JQ_COND="true"
if [ -n "$SOURCE" ]; then
    JQ_COND="$JQ_COND and ((.source // .source_type // .log_source // \"\") == \"$SOURCE\")"
fi
if [ -n "$HOST" ]; then
    JQ_COND="$JQ_COND and ((.host // .hostname // .source_host // \"\") == \"$HOST\")"
fi
if [ -n "$CATEGORY" ]; then
    JQ_COND="$JQ_COND and ((.category // .event_category // \"\") == \"$CATEGORY\")"
fi
if [ -n "$FROM" ]; then
    JQ_COND="$JQ_COND and ((.timestamp // .time // .@timestamp // \"\") >= \"$FROM\")"
fi
if [ -n "$TO" ]; then
    JQ_COND="$JQ_COND and ((.timestamp // .time // .@timestamp // \"\") <= \"$TO\")"
fi

# Execute requested sub-command
case "$VERB" in
    filter)
        jq -c ".[] | select($JQ_COND)" "$DATA_FILE"
        ;;
    count)
        jq -r "[.[] | select($JQ_COND)] | length" "$DATA_FILE"
        ;;
    distinct)
        if [ -z "$FIELD" ]; then
            echo "Error: --field is required for 'distinct'" >&2
            exit 1
        fi
        jq -r --arg f "$FIELD" "[.[] | select($JQ_COND) | .[$f] // empty] | unique[]" "$DATA_FILE"
        ;;
    top)
        if [ -z "$FIELD" ]; then
            echo "Error: --field is required for 'top'" >&2
            exit 1
        fi
        jq -r --arg f "$FIELD" --argjson lim "$LIMIT" '
            [.[] | select('"$JQ_COND"') | .[$f] // "N/A"] 
            | group_by(.) 
            | map({value: .[0], count: length}) 
            | sort_by(.count) 
            | reverse 
            | .[0:$lim] 
            | .[] 
            | "\(.count)\t\(.value)"
        ' "$DATA_FILE"
        ;;
    window)
        if [ -z "$FIELD" ] || [ -z "$BUCKET" ]; then
            echo "Error: Both --field and --bucket (<hour|day>) are required for 'window'" >&2
            exit 1
        fi
        if [ "$BUCKET" = "hour" ]; then
            jq -r --arg f "$FIELD" '
                [.[] | select('"$JQ_COND"') | .[$f] // .timestamp // .time // ""] 
                | map(select(length >= 13) | .[0:13]) 
                | group_by(.) 
                | map({bucket: .[0], count: length}) 
                | sort_by(.bucket) 
                | .[] 
                | "\(.bucket)\t\(.count)"
            ' "$DATA_FILE"
        elif [ "$BUCKET" = "day" ]; then
            jq -r --arg f "$FIELD" '
                [.[] | select('"$JQ_COND"') | .[$f] // .timestamp // .time // ""] 
                | map(select(length >= 10) | .[0:10]) 
                | group_by(.) 
                | map({bucket: .[0], count: length}) 
                | sort_by(.bucket) 
                | .[] 
                | "\(.bucket)\t\(.count)"
            ' "$DATA_FILE"
        else
            echo "Error: Invalid bucket type. Use 'hour' or 'day'." >&2
            exit 1
        fi
        ;;
    *)
        echo "Error: Unknown verb '$VERB'" >&2
        print_help
        exit 1
        ;;
es:
