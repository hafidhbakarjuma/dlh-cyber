#!/bin/bash
# ==============================================================================
# Script Name: 1-symmetric_encrypt.sh
# Purpose: Encrypt files using AES-256 (CBC or GCM mode) for MedDefense Systems
# Usage: ./1-symmetric_encrypt.sh <input_file> <output_file> <cbc|gcm>
# ==============================================================================

set -euo pipefail

# Check arguments
if [ "$#" -ne 3 ]; then
    echo "[-] Error: Invalid arguments."
    echo "Usage: $0 <input_file> <output_file> <cbc|gcm>"
    exit 1
fi

INPUT_FILE="$1"
OUTPUT_FILE="$2"
MODE=$(echo "$3" | tr '[:upper:]' '[:lower:]')

# Validate input file existence
if [ ! -f "$INPUT_FILE" ]; then
    echo "[-] Error: Input file '$INPUT_FILE' not found."
    exit 1
fi

# Prompt securely for encryption password
echo -n "[?] Enter encryption password: "
read -rs PASSWORD
echo
echo -n "[?] Confirm encryption password: "
read -rs PASSWORD_CONFIRM
echo

if [ "$PASSWORD" != "$PASSWORD_CONFIRM" ]; then
    echo "[-] Error: Passwords do not match."
    exit 1
fi

# Execute encryption based on selected mode
case "$MODE" in
    cbc)
        echo "[*] Encrypting $INPUT_FILE using AES-256-CBC..."
        openssl enc -aes-256-cbc -salt -in "$INPUT_FILE" -out "$OUTPUT_FILE" -k "$PASSWORD"
        echo "[+] Success: Encrypted output saved to $OUTPUT_FILE (Mode: AES-256-CBC)"
        ;;
    gcm)
        echo "[*] Encrypting $INPUT_FILE using AES-256-GCM..."
        openssl enc -aes-256-gcm -salt -in "$INPUT_FILE" -out "$OUTPUT_FILE" -k "$PASSWORD"
        echo "[+] Success: Encrypted output saved to $OUTPUT_FILE (Mode: AES-256-GCM)"
        ;;
    *)
        echo "[-] Error: Unsupported mode '$MODE'. Choose 'cbc' or 'gcm'."
        exit 1
        ;;
esac
