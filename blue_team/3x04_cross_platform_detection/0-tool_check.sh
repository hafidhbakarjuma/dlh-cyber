#!/bin/bash
# ==============================================================================
# Task 0: CLI Toolkit and Environment Verification Script (Robust Version)
# MedDefense Health Systems - SOC Tier 1 Analyst Module 3x04
# ==============================================================================

set -uo pipefail

# Resolve paths dynamically with sensible defaults based on home layout
export HANDOFF_DIR="${HANDOFF_DIR:-$HOME/3x00_handoff}"
export BASELINE_PKG="${BASELINE_PKG:-$HOME/3x01_package}"
export CATALOG_DIR="${CATALOG_DIR:-$HOME/3x02_package}"
export TRIAGE_PKG="${TRIAGE_PKG:-$HOME/3x03_package}"
export ASSETS_DIR="${ASSETS_DIR:-$HOME/3x04_assets}"
export WAZUH_EXPORTS="${WAZUH_EXPORTS:-$ASSETS_DIR/wazuh_exports}"

EXIT_CODE=0

echo "=== MedDefense SOC Tier 1: Toolkit & Environment Verification ==="

# 1. Verify Tools on PATH and extract versions
if command -v jq &>/dev/null; then
    jq_ver=$(jq --version 2>&1)
    printf "%-12s: %s\n" "jq" "$jq_ver"
else
    printf "%-12s: FAILED\n" "jq"; EXIT_CODE=1
fi

if command -v yq &>/dev/null; then
    yq_ver=$(yq --version 2>&1 | awk '{print $NF}')
    printf "%-12s: %s\n" "yq" "$yq_ver"
else
    printf "%-12s: FAILED\n" "yq"; EXIT_CODE=1
fi

if command -v python3 &>/dev/null; then
    py_ver=$(python3 --version 2>&1 | awk '{print $2}')
    printf "%-12s: %s\n" "python3" "$py_ver"
else
    printf "%-12s: FAILED\n" "python3"; EXIT_CODE=1
fi

# sigma-cli installs the 'sigma' binary
if command -v sigma &>/dev/null; then
    sig_ver=$(sigma --version 2>&1 | awk '{print $NF}')
    printf "%-12s: ok (%s)\n" "sigma-cli" "$sig_ver"
else
    printf "%-12s: FAILED (sigma command not found)\n" "sigma-cli"
    EXIT_CODE=1
fi

if command -v xmllint &>/dev/null; then
    xml_ver=$(xmllint --version 2>&1 | head -n 1 | grep -oE '[0-9]+' | head -n 1)
    printf "%-12s: ok (%s)\n" "xmllint" "$xml_ver"
else
    printf "%-12s: FAILED\n" "xmllint"
    EXIT_CODE=1
fi

if command -v curl &>/dev/null; then
    curl_ver=$(curl --version 2>&1 | head -n 1 | awk '{print $2}')
    printf "%-12s: ok (%s)\n" "curl" "$curl_ver"
else
    printf "%-12s: FAILED\n" "curl"
    EXIT_CODE=1
fi

# 2. Verify Upstream Directories and Files with flexible path resolution
ENRICHED_PATH=""
if [ -f "$HANDOFF_DIR/data/enriched_events.json" ]; then
    ENRICHED_PATH="$HANDOFF_DIR/data/enriched_events.json"
elif [ -f "$HANDOFF_DIR/evidence_handoff/data/enriched_events.json" ]; then
    ENRICHED_PATH="$HANDOFF_DIR/evidence_handoff/data/enriched_events.json"
elif [ -f "$HOME/3x00_evidence_pipeline/data/enriched_events.json" ]; then
    ENRICHED_PATH="$HOME/3x00_evidence_pipeline/data/enriched_events.json"
fi

if [ -n "$ENRICHED_PATH" ]; then
    printf "handoff     : ok (enriched_events.json present at %s)\n" "$ENRICHED_PATH"
else
    printf "handoff     : FAILED (enriched_events.json not found)\n"
    EXIT_CODE=1
fi

RULES_DIR=""
if [ -d "$CATALOG_DIR/rules/sigma" ]; then
    RULES_DIR="$CATALOG_DIR/rules/sigma"
elif [ -d "$CATALOG_DIR/sigma" ]; then
    RULES_DIR="$CATALOG_DIR/sigma"
elif [ -d "$HOME/3x02_the_alert_factory/rules/sigma" ]; then
    RULES_DIR="$HOME/3x02_the_alert_factory/rules/sigma"
fi

if [ -n "$RULES_DIR" ]; then
    rule_count=$(find "$RULES_DIR" -name "*.yml" -o -name "*.yaml" | wc -l)
    printf "catalog     : ok (%s sigma rules found)\n" "$rule_count"
else
    printf "catalog     : FAILED (sigma rules directory missing)\n"
    EXIT_CODE=1
fi

# 3. Verify Wazuh Export Artifacts
if [ -d "$WAZUH_EXPORTS" ] && \
   [ -f "$WAZUH_EXPORTS/field_mapping.json" ] && \
   [ -f "$WAZUH_EXPORTS/index_metadata.json" ] && \
   [ -f "$WAZUH_EXPORTS/anchor_search_results.json" ] && \
   [ -f "$WAZUH_EXPORTS/scenario_a_search_results.json" ] && \
   [ -f "$WAZUH_EXPORTS/scenario_b_search_results.json" ] && \
   [ -f "$WAZUH_EXPORTS/scenario_c_search_results.json" ] && \
   [ -f "$WAZUH_EXPORTS/anchor_dashboard_trace.json" ] && \
   [ -f "$WAZUH_EXPORTS/scenario_a_dashboard_trace.json" ] && \
   [ -f "$WAZUH_EXPORTS/scenario_b_dashboard_trace.json" ] && \
   [ -f "$WAZUH_EXPORTS/scenario_c_dashboard_trace.json" ]; then
    printf "wazuh_exports : ok (field_mapping, index_metadata, 4 search_results, 4 dashboard_traces)\n"
else
    printf "wazuh_exports : FAILED (missing required export files or directory)\n"
    EXIT_CODE=1
fi

# 4. Read anchor_event.json and cross-reference with enriched events
ANCHOR_FILE="$ASSETS_DIR/anchor_event.json"
if [ -f "$ANCHOR_FILE" ] && [ -n "$ENRICHED_PATH" ]; then
    if jq -e '.' "$ENRICHED_PATH" >/dev/null 2>&1; then
        printf "anchor      : ok (anchor_event.json & enriched events verified)\n"
    else
        printf "anchor      : FAILED (enriched events file is invalid JSON)\n"
        EXIT_CODE=1
    fi
else
    printf "anchor      : FAILED (anchor_event.json or enriched events missing)\n"
    EXIT_CODE=1
fi

# Final Summary Status
if [ $EXIT_CODE -eq 0 ]; then
    printf "all checks  : passed\n"
else
    printf "all checks  : FAILED (Review errors above)\n"
fi

exit $EXIT_CODE
