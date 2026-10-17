#!/bin/bash
# verify_artifacts.sh - Artifact Integrity Verification Script
# Case: LH-2026-0414-01

HASHES_FILE="hashes.txt"
LOG_FILE="verification_log.txt"
ACTOR="${USER:-analyst}"
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

declare -A ARTIFACTS=(
    ["ART-001"]="wst-ws-031.dd"
    ["ART-002"]="wst-ws-031.mem"
    ["ART-003"]="wst-ws-017.mem"
)

if ! command -v sha256sum &> /dev/null; then
    echo "Error: sha256sum utility not found." >&2
    exit 1
fi

# Baseline establishment mode if hashes.txt does not exist
if [ ! -f "$HASHES_FILE" ]; then
    touch "$HASHES_FILE"
    for id in ART-001 ART-002 ART-003; do
        file="${ARTIFACTS[$id]}"
        if [ -f "$file" ]; then
            hash=$(sha256sum "$file" | awk '{print $1}')
            echo "$id $file $hash" >> "$HASHES_FILE"
            echo "[BASELINE_SET] $id $file  sha256=$hash"
            echo "$TIMESTAMP,$ACTOR,$id,BASELINE_SET,$hash,$hash" >> "$LOG_FILE"
        else
            echo "Error: Required artifact $file not found for baseline establishment." >&2
            exit 1
        fi
    done
    echo "Baseline written to hashes.txt. Run again to verify."
    exit 0
fi

# Verification mode
FAILED=0
for id in ART-001 ART-002 ART-003; do
    file="${ARTIFACTS[$id]}"
    
    if [ ! -f "$file" ]; then
        echo "[FAIL] $id $file  expected=EXISTS computed=MISSING"
        echo "$TIMESTAMP,$ACTOR,$id,FAIL,MISSING,MISSING" >> "$LOG_FILE"
        FAILED=1
        continue
    fi
    
    computed=$(sha256sum "$file" | awk '{print $1}')
    expected=$(grep "^$id " "$HASHES_FILE" | awk '{print $3}')
    
    if [ -z "$expected" ]; then
        expected="UNKNOWN"
    fi
    
    if [ "$computed" = "$expected" ]; then
        echo "[PASS] $id $file  expected=$expected computed=$computed"
        echo "$TIMESTAMP,$ACTOR,$id,PASS,$expected,$computed" >> "$LOG_FILE"
    else
        echo "[FAIL] $id $file  expected=$expected computed=$computed"
        echo "$TIMESTAMP,$ACTOR,$id,FAIL,$expected,$computed" >> "$LOG_FILE"
        FAILED=1
    fi
done

if [ $FAILED -eq 0 ]; then
    echo "ALL ARTIFACTS VERIFIED"
    exit 0
else
    exit 1
fi
