#!/bin/bash
# ==============================================================================
# Script Name: 5-sign_verify.sh
# Purpose: Sign files or verify digital signatures using OpenSSL & SHA-256
# ==============================================================================

set -euo pipefail

if [ "$#" -lt 1 ]; then
    echo "[-] Error: Missing mode argument."
    echo "Usage: $0 [sign|verify] ..."
    exit 1
fi

MODE=$(echo "$1" | tr '[:upper:]' '[:lower:]')
shift

case "$MODE" in
    sign)
        if [ "$#" -ne 2 ]; then
            echo "[-] Error: 'sign' mode requires a file path and a private key path."
            echo "Usage: $0 sign <file_path> <private_key_path>"
            exit 1
        fi
        
        FILE_PATH="$1"
        PRIVATE_KEY="$2"
        SIG_FILE="${FILE_PATH}.sig"

        if [ ! -f "$FILE_PATH" ]; then
            echo "[-] Error: File '$FILE_PATH' not found."
            exit 1
        fi
        if [ ! -f "$PRIVATE_KEY" ]; then
            echo "[-] Error: Private key '$PRIVATE_KEY' not found."
            exit 1
        fi

        echo "[*] Signing $FILE_PATH with SHA-256 and $PRIVATE_KEY..."
        openssl dgst -sha256 -sign "$PRIVATE_KEY" -out "$SIG_FILE" "$FILE_PATH"
        echo "[+] Success: Signature written to $SIG_FILE"
        exit 0
        ;;

    verify)
        if [ "$#" -ne 3 ]; then
            echo "[-] Error: 'verify' mode requires a file path, signature path, and public key path."
            echo "Usage: $0 verify <file_path> <signature_path> <public_key_path>"
            exit 1
        fi

        FILE_PATH="$1"
        SIG_FILE="$2"
        PUBLIC_KEY="$3"

        if [ ! -f "$FILE_PATH" ]; then
            echo "[-] Error: File '$FILE_PATH' not found."
            exit 1
        fi
        if [ ! -f "$SIG_FILE" ]; then
            echo "[-] Error: Signature file '$SIG_FILE' not found."
            exit 1
        fi
        if [ ! -f "$PUBLIC_KEY" ]; then
            echo "[-] Error: Public key '$PUBLIC_KEY' not found."
            exit 1
        fi

        echo "[*] Verifying signature for $FILE_PATH..."
        if openssl dgst -sha256 -verify "$PUBLIC_KEY" -signature "$SIG_FILE" "$FILE_PATH"; then
            echo "[+] VERIFICATION SUCCESS: Signature is valid."
            exit 0
        else
            echo "[-] VERIFICATION FAILURE: Signature is invalid or file has been tampered with."
            exit 1
        fi
        ;;

    *)
        echo "[-] Error: Unknown mode '$MODE'. Use 'sign' or 'verify'."
        exit 1
        ;;
esac
