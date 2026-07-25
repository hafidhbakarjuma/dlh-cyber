#!/bin/bash
# ==============================================================================
# Script Name: 3-hash_verify.sh
# Purpose: Verify SHA-256 file integrity against an expected hash digest
# Usage: ./3-hash_verify.sh <file_path> <expected_sha256_hash>
# ==============================================================================

set -euo pipefail

# Check argument count
if [ "$#" -ne 2 ]; then
    echo "[-] Error: Invalid arguments."
    echo "Usage: $0 <file_path> <expected_sha256_hash>"
    exit 1
fi

FILE_PATH="$1"
EXPECTED_HASH=$(echo "$2" | tr '[:upper:]' '[:lower:]')

# Validate file existence
if [ ! -f "$FILE_PATH" ]; then
    echo "[-] Error: File '$FILE_PATH' not found."
    exit 1
fi

# Compute actual SHA-256 hash
echo "[*] Computing SHA-256 hash for $FILE_PATH..."
ACTUAL_HASH=$(sha256sum "$FILE_PATH" | awk '{print $1}')

# Compare actual vs expected hash
if [ "$ACTUAL_HASH" == "$EXPECTED_HASH" ]; then
    echo "[+] INTEGRITY OK"
    exit 0
else
    echo "[-] INTEGRITY FAILED - expected $EXPECTED_HASH got $ACTUAL_HASH"
    exit 1
fi
