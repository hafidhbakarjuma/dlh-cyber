#!/usr/bin/
# ==============================================================================
# Script Name: 10-generate_csr.sh
# Description: Automates private key generation and CSR creation for MedDefense Portal
# ==============================================================================

set -e

CONFIG_FILE="openssl.cnf"
KEY_FILE="portal_key.pem"
CSR_FILE="portal.csr"

echo "[*] Step 1: Generating OpenSSL configuration file (${CONFIG_FILE})..."
cat << 'EOF' > "${CONFIG_FILE}"
[ req ]
default_bits       = 4096
distinguished_name = req_distinguished_name
req_extensions     = req_ext
prompt             = no

[ req_distinguished_name ]
C  = US
ST = California
L  = San Francisco
O  = MedDefense Health Systems
OU = Information Technology
CN = portal.meddefense.local

[ req_ext ]
subjectAltName = @alt_names

[ alt_names ]
DNS.1 = portal.meddefense.local
DNS.2 = www.portal.meddefense.local
DNS.3 = secure.meddefense.local
EOF

echo "[*] Step 2: Generating 4096-bit RSA Private Key (${KEY_FILE})..."
openssl genpkey -algorithm RSA -out "${KEY_FILE}" -pkeyopt rsa_keygen_bits:4096
chmod 600 "${KEY_FILE}"

echo "[*] Step 3: Generating Certificate Signing Request (${CSR_FILE})..."
openssl req -new -key "${KEY_FILE}" -out "${CSR_FILE}" -config "${CONFIG_FILE}"

echo "[*] Success! CSR generated and verified:"
openssl req -text -noout -in "${CSR_FILE}" | grep -E "Subject:|DNS:"

echo "[*] Done. Ready for submission to CA."
