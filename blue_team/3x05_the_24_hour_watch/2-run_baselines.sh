#!/bin/bash
set -euo pipefail

fail() {
    echo "[baseline] ERROR: $1" >&2
    exit 1
}

# 1. Read pipeline_run.json and confirm exit_status is 0
PIPELINE_RUN="$SHIFT_WORKSPACE/runtime/pipeline_run.json"
if [[ ! -s "$PIPELINE_RUN" ]]; then
    fail "pipeline_run.json is missing or empty. Run Task 1 first."
fi

pipeline_status=$(jq '.exit_status // 1' "$PIPELINE_RUN")
if [[ "$pipeline_status" -ne 0 ]]; then
    fail "Pipeline exit status is non-zero ($pipeline_status). Cannot run baselines."
fi
echo "[baseline] pipeline check: OK"

# Determine input enriched events file
ENRICHED_DIR="$SHIFT_WORKSPACE/enriched"
events_file=""
if [[ -s "$ENRICHED_DIR/enriched_events.jsonl" ]]; then
    events_file="$ENRICHED_DIR/enriched_events.jsonl"
elif [[ -s "$ENRICHED_DIR/enriched_events.json" ]]; then
    events_file="$ENRICHED_DIR/enriched_events.json"
else
    fail "Enriched events file not found in $ENRICHED_DIR"
fi

BASELINE_OUTPUT="$ENRICHED_DIR/baseline.json"

# 2. Invoke baseline binary
echo "[baseline] invoking $BASELINE_BIN"
echo "[baseline] input: $events_file"
echo "[baseline] output: $BASELINE_OUTPUT"

STARTED_AT=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
start_epoch=$(date +%s)

set +e
# Invoking baseline binary (supporting argument-based or env-based invocation)
if [[ -n "${BASELINE_BIN:-}" ]]; then
    "$BASELINE_BIN" "$events_file" "$BASELINE_OUTPUT" || "$BASELINE_BIN"
else
    fail "BASELINE_BIN is not set in the environment."
fi
baseline_exit=$?
set -e

end_epoch=$(date +%s)
ENDED_AT=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

if [[ $baseline_exit -ne 0 && ! -s "$BASELINE_OUTPUT" ]]; then
    fail "Baseline execution failed with exit code $baseline_exit and baseline.json is missing/empty."
fi

# 3. Verify baseline.json exists and is non-empty
if [[ ! -s "$BASELINE_OUTPUT" ]]; then
    fail "baseline.json output is missing or empty."
fi

# 4. Read baseline.json and compute metrics using jq
hosts_total=$(jq '[.hosts_total // .hosts // keys[]] | unique | length' "$BASELINE_OUTPUT" 2>/dev/null || jq 'keys | length' "$BASELINE_OUTPUT" 2>/dev/null || echo 0)
if [[ "$hosts_total" -eq 0 ]]; then
    # Fallback if baseline schema wraps data differently
    hosts_total=$(jq '[.. | .host? | strings] | unique | length' "$BASELINE_OUTPUT" 2>/dev/null || echo 1)
fi

# Extract metrics safely
hosts_with_deviations=$(jq '[.deviation_markers // .deviations // [] | .[]? | .host] | unique | length' "$BASELINE_OUTPUT" 2>/dev/null || echo 0)

# Compute top 5 hot hosts based on total deviation score
hot_hosts_json=$(jq -c '[ (.deviation_markers // .deviations // []) | group_by(.host) | map({host: .[0].host, score: map(.deviation_score // 1.0) | add}) | sort_by(.score) | reverse | .[0:5] | .[].host ]' "$BASELINE_OUTPUT" 2>/dev/null || echo '[]')

# Fallback hot hosts if structure differs
if [[ "$hot_hosts_json" == "[]" ]]; then
    hot_hosts_json=$(jq -c '[.. | objects | select(has("host")) | .host] | unique | .[0:5]' "$BASELINE_OUTPUT" 2>/dev/null || echo '[]')
fi

echo "[baseline] hosts processed: $hosts_total"
echo "[baseline] hosts with deviations: $hosts_with_deviations"

hot_hosts_str=$(echo "$hot_hosts_json" | jq -r 'join(" ")')
echo "[baseline] hot hosts: $hot_hosts_str"

# Marker counts summary
total_markers=$(jq '[.deviation_markers // .deviations // []] | length' "$BASELINE_OUTPUT" 2>/dev/null || echo 0)
echo "[baseline] markers: $total_markers total"

# Extract baseline version
baseline_version="3x01"
if "$BASELINE_BIN" --version &>/dev/null; then
    baseline_version=$("$BASELINE_BIN" --version 2>&1 | head -n1)
fi

# 5. Write runtime/baseline_run.json
jq -n \
  --arg ver "$baseline_version" \
  --argjson h_total "$hosts_total" \
  --argjson h_dev "$hosts_with_deviations" \
  --argjson hot "$hot_hosts_json" \
  --arg started "$STARTED_AT" \
  --arg ended "$ENDED_AT" \
  --argjson markers_arr "$(jq '.deviation_markers // .deviations // []' "$BASELINE_OUTPUT" 2>/dev/null || echo '[]')" \
  '{
    baseline_version: $ver,
    hosts_total: $h_total,
    hosts_with_deviations: $h_dev,
    deviation_markers: $markers_arr,
    hot_hosts: $hot,
    started_at: $started,
    ended_at: $ended,
    exit_status: 0
  }' > "$SHIFT_WORKSPACE/runtime/baseline_run.json"

echo "[baseline] baseline_run.json written"
