#!/bin/bash
# =============================================================================
# generate_sm2_certs.sh - Generate SM2 Certificates for TLCP
# =============================================================================
#
# TLCP requires two certificate pairs per entity:
# - Sign certificate (for digital signature/authentication)
# - Enc certificate (for key exchange/encryption)
#
# Usage:
#   ./generate_sm2_certs.sh <common_name> [output_dir] [days]
#
# Example:
#   ./generate_sm2_certs.sh myserver.example.com ./certs 365
# =============================================================================

set -e

CN="${1:-localhost}"
OUT_DIR="${2:-.}"
DAYS="${3:-365}"
CA_DAYS="${4:-3650}"

# Find Tongsuo
if [ -n "$TONGSUO_ROOT_ACTIVE" ]; then
    TONGSUO_ROOT="$TONGSUO_ROOT_ACTIVE"
else
    TONGSUO_ROOT=$(ls -d /opt/tongsuo-* 2>/dev/null | sort -V | tail -1)
fi

if [ -z "$TONGSUO_ROOT" ] || [ ! -d "$TONGSUO_ROOT" ]; then
    echo "Fehler: Tongsuo nicht installiert"
    echo "Bitte zuerst installieren: ./install_tongsuo.sh"
    exit 1
fi

OPENSSL="$TONGSUO_ROOT/bin/openssl"

echo "============================================"
echo " SM2 Certificate Generator for TLCP"
echo "============================================"
echo ""
echo "Common Name:  $CN"
echo "Output Dir:   $OUT_DIR"
echo "Validity:     $DAYS days (CA: $CA_DAYS days)"
echo "Tongsuo:      $TONGSUO_ROOT"
echo ""

mkdir -p "$OUT_DIR"
cd "$OUT_DIR"

# Create OpenSSL config for SM2
cat > sm2_openssl.cnf << 'EOF'
[req]
default_bits = 256
default_md = sm3
distinguished_name = req_dn
x509_extensions = v3_ca
prompt = no

[req_dn]
CN = SM2 Test CA
O = Test Organization
C = CN

[v3_ca]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical,CA:true
keyUsage = critical,keyCertSign,cRLSign

[v3_sign]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
basicConstraints = CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = serverAuth,clientAuth

[v3_enc]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
basicConstraints = CA:FALSE
keyUsage = critical,keyEncipherment,dataEncipherment,keyAgreement
extendedKeyUsage = serverAuth,clientAuth
EOF

echo "1. Generating SM2 CA..."
$OPENSSL genpkey -algorithm SM2 -out sm2_ca.key
$OPENSSL req -new -x509 -key sm2_ca.key -out sm2_ca.crt -days $CA_DAYS \
    -subj "/CN=SM2 Root CA/O=Test Organization/C=CN" -sm3
echo "   OK - sm2_ca.key, sm2_ca.crt"

echo ""
echo "2. Generating SM2 Sign Certificate (for authentication)..."
$OPENSSL genpkey -algorithm SM2 -out sm2_sign.key
$OPENSSL req -new -key sm2_sign.key -out sm2_sign.csr \
    -subj "/CN=$CN/O=Test Organization/C=CN" -sm3 -config sm2_openssl.cnf
$OPENSSL x509 -req -in sm2_sign.csr -CA sm2_ca.crt -CAkey sm2_ca.key \
    -out sm2_sign.crt -days $DAYS -sm3 -CAcreateserial \
    -extfile sm2_openssl.cnf -extensions v3_sign
echo "   OK - sm2_sign.key, sm2_sign.crt"

echo ""
echo "3. Generating SM2 Enc Certificate (for key exchange)..."
$OPENSSL genpkey -algorithm SM2 -out sm2_enc.key
$OPENSSL req -new -key sm2_enc.key -out sm2_enc.csr \
    -subj "/CN=$CN/O=Test Organization/C=CN" -sm3 -config sm2_openssl.cnf
$OPENSSL x509 -req -in sm2_enc.csr -CA sm2_ca.crt -CAkey sm2_ca.key \
    -out sm2_enc.crt -days $DAYS -sm3 -CAcreateserial \
    -extfile sm2_openssl.cnf -extensions v3_enc
echo "   OK - sm2_enc.key, sm2_enc.crt"

echo ""
echo "4. Creating certificate chain and bundles..."
cat sm2_sign.crt sm2_ca.crt > sm2_sign_chain.crt
cat sm2_enc.crt sm2_ca.crt > sm2_enc_chain.crt
echo "   OK - sm2_sign_chain.crt, sm2_enc_chain.crt"

# Create combined PEM files for easier use
cat sm2_sign.key sm2_sign.crt > sm2_sign.pem
cat sm2_enc.key sm2_enc.crt > sm2_enc.pem

# Set permissions
chmod 600 *.key *.pem
chmod 644 *.crt

# Cleanup temp files
rm -f sm2_openssl.cnf *.csr *.srl

echo ""
echo "============================================"
echo " SM2 Certificates Generated"
echo "============================================"
echo ""
echo "CA Certificate:"
echo "  sm2_ca.crt          - Root CA certificate"
echo "  sm2_ca.key          - Root CA private key"
echo ""
echo "Sign Certificate (Authentication):"
echo "  sm2_sign.crt        - Sign certificate"
echo "  sm2_sign.key        - Sign private key"
echo "  sm2_sign_chain.crt  - Sign cert + CA chain"
echo "  sm2_sign.pem        - Combined key + cert"
echo ""
echo "Enc Certificate (Key Exchange):"
echo "  sm2_enc.crt         - Encryption certificate"
echo "  sm2_enc.key         - Encryption private key"
echo "  sm2_enc_chain.crt   - Enc cert + CA chain"
echo "  sm2_enc.pem         - Combined key + cert"
echo ""
echo "TLCP Server Configuration:"
echo "  Sign cert: sm2_sign_chain.crt + sm2_sign.key"
echo "  Enc cert:  sm2_enc_chain.crt + sm2_enc.key"
echo "  CA:        sm2_ca.crt"
echo ""

# Verify certificates
echo "Verification:"
echo -n "  Sign cert: "
$OPENSSL verify -CAfile sm2_ca.crt sm2_sign.crt 2>/dev/null && echo "OK" || echo "FAIL"
echo -n "  Enc cert:  "
$OPENSSL verify -CAfile sm2_ca.crt sm2_enc.crt 2>/dev/null && echo "OK" || echo "FAIL"
