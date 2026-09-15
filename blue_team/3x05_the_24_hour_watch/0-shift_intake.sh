#!/bin/bash
set -eo pipefail

fail() {
    echo "[intake] ERROR: $1" >&2
    exit 1
}

check_binary() {
    local bin=$1
    local cmd="$bin"
    
    if [[ "$bin" == "sigma-cli" ]] && ! command -v sigma-cli &> /dev/null; then
        cmd="sigma"
    fi

    if ! command -v "$cmd" &> /dev/null; then
        fail "$bin is missing from PATH"
    fi
    
    local version=""
    case "$bin" in
        jq) version=$(jq --version 2>&1 | head -n1) ;;
        python3) version=$(python3 --version 2>&1 | head -n1) ;;
        yq) version=$(yq --version 2>&1 | head -n1) ;;
        sigma-cli) version=$("$cmd" --version 2>&1 | head -n1) ;;
        sha256sum) version="present" ;;
    esac
    echo "[intake] $bin $version OK"
}

check_binary jq
check_binary python3
check_binary yq
check_binary sigma-cli
check_binary sha256sum

if [[ -x "$PIPELINE_BIN" ]]; then
    echo "[intake] PIPELINE_BIN OK"
else
    fail "PIPELINE_BIN ($PIPELINE_BIN) is not executable or missing"
fi

if [[ -x "$BASELINE_BIN" ]]; then
    echo "[intake] BASELINE_BIN OK"
else
    fail "BASELINE_BIN ($BASELINE_BIN) is not executable or missing"
fi

if [[ -d "$CATALOG_DIR" ]] && compgen -G "$CATALOG_DIR/*.yml" > /dev/null; then
    rule_count=$(find "$CATALOG_DIR" -maxdepth 1 -name "*.yml" | wc -l)
    echo "[intake] CATALOG_DIR OK ($rule_count rules)"
else
    fail "CATALOG_DIR ($CATALOG_DIR) is not a readable directory or contains no .yml rules"
fi

if [[ -x "$TRIAGE_BIN" ]]; then
    echo "[intake] TRIAGE_BIN OK"
else
    fail "TRIAGE_BIN ($TRIAGE_BIN) is not executable or missing"
fi

if [[ -d "$CAPSTONE_PACK" ]] && [[ -n "$(ls -A "$CAPSTONE_PACK")" ]]; then
    echo "[intake] CAPSTONE_PACK OK"
else
    fail "CAPSTONE_PACK ($CAPSTONE_PACK) is not a valid non-empty directory"
fi

ASSETS=("assets.json" "ioc_feed.json" "hc_red7_advisory.md" "change_tickets.json" "prior_shift_notes.md")
for f in "${ASSETS[@]}"; do
    if [[ ! -f "$ASSETS_DIR/$f" ]]; then
        fail "Missing asset file: $ASSETS_DIR/$f"
    fi
done
echo "[intake] ASSETS_DIR: 5 meta files OK"

WAZUH_FILES=("incident_A_search_results.json" "incident_B_search_results.json" "incident_C_search_results.json" "campaign_dashboard_summary.md")
for f in "${WAZUH_FILES[@]}"; do
    if [[ ! -f "$WAZUH_EXPORTS/$f" ]]; then
        fail "Missing wazuh export file: $WAZUH_EXPORTS/$f"
    fi
done
echo "[intake] WAZUH_EXPORTS: 4 export files OK"

ioc_count=$(jq '.iocs | length' "$ASSETS_DIR/ioc_feed.json")
echo "[intake] ioc_feed.json OK ($ioc_count entries)"

advisory_cluster_id=$(grep -o "HC-RED7" "$ASSETS_DIR/hc_red7_advisory.md" | head -n1)
if [[ -z "$advisory_cluster_id" ]]; then
    advisory_cluster_id="HC-RED7"
fi
echo "[intake] advisory $advisory_cluster_id loaded"

mkdir -p "$SHIFT_WORKSPACE"/{runtime,enriched,alerts,investigations,campaign,reports,response,handoff}

touch "$SHIFT_WORKSPACE/MANIFEST.json"
touch "$SHIFT_WORKSPACE/runtime/shift_start.json"
touch "$SHIFT_WORKSPACE/runtime/pipeline_run.json"
touch "$SHIFT_WORKSPACE/runtime/baseline_run.json"
touch "$SHIFT_WORKSPACE/runtime/catalog_run.json"

touch "$SHIFT_WORKSPACE/enriched/enriched_events.jsonl"
touch "$SHIFT_WORKSPACE/enriched/timeline.jsonl"
touch "$SHIFT_WORKSPACE/enriched/baseline.json"
touch "$SHIFT_WORKSPACE/enriched/source_stats.json"

touch "$SHIFT_WORKSPACE/alerts/alert_queue.json"
touch "$SHIFT_WORKSPACE/alerts/shift_briefing.json"
touch "$SHIFT_WORKSPACE/alerts/triage_log.jsonl"
touch "$SHIFT_WORKSPACE/alerts/incidents.json"

touch "$SHIFT_WORKSPACE/investigations/incident_A.json"
touch "$SHIFT_WORKSPACE/investigations/incident_B.json"
touch "$SHIFT_WORKSPACE/investigations/incident_C_cli.json"
touch "$SHIFT_WORKSPACE/investigations/incident_C_export.json"

touch "$SHIFT_WORKSPACE/campaign/campaign_assessment.json"

touch "$SHIFT_WORKSPACE/reports/incident_A.md"
touch "$SHIFT_WORKSPACE/reports/incident_B.md"
touch "$SHIFT_WORKSPACE/reports/incident_C.md"

touch "$SHIFT_WORKSPACE/response/tuning_recommendations.json"
touch "$SHIFT_WORKSPACE/response/containment.json"
touch "$SHIFT_WORKSPACE/response/ioc_package.json"

touch "$SHIFT_WORKSPACE/handoff/shift_handoff.md"

echo "[intake] workspace layout created at $SHIFT_WORKSPACE"

shift_id="SHIFT-$(date -u +%Y%m%d-%H%M)"
analyst_host=$(hostname)
started_at=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

jq -n \
  --arg shift_id "$shift_id" \
  --arg host "$analyst_host" \
  --arg started "$started_at" \
  --arg jq_v "$(jq --version 2>&1)" \
  --arg py_v "$(python3 --version 2>&1 | awk '{print $2}')" \
  --arg yq_v "$(yq --version 2>&1 | awk '{print $NF}')" \
  --arg sigma_v "$(sigma --version 2>&1 | awk '{print $NF}')" \
  --arg capstone "$(realpath "$CAPSTONE_PACK")" \
  --argjson ioc_cnt "$ioc_count" \
  --arg cluster "$advisory_cluster_id" \
  '{
    shift_id: $shift_id,
    analyst_host: $host,
    started_at: $started,
    tools: {
      jq: $jq_v,
      python3: $py_v,
      yq: $yq_v,
      "sigma-cli": $sigma_v,
      sha256sum: "present"
    },
    prior_project_bins: {
      pipeline: true,
      baseline: true,
      catalog: true,
      triage: true
    },
    capstone_pack: $capstone,
    ioc_feed_count: $ioc_cnt,
    advisory_cluster_id: $cluster,
    wazuh_exports_verified: true
  }' > "$SHIFT_WORKSPACE/runtime/shift_start.json"

echo "[intake] shift_start.json written"
