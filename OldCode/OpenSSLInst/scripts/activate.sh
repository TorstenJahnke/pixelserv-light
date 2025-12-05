#!/bin/bash
# configure_tlcp_tls.sh - Konfiguriere TLCP und TLS SM Cipher Suites

source /opt/openssl-3.6.0/scripts/activate.sh

echo "🔧 Konfiguriere TLCP 1.1 und TLS SM Cipher Suites..."

# Teste verfügbare Cipher Suites
echo "Verfügbare SM Cipher Suites:"
openssl ciphers -v | grep -E "(SM2|SM3|SM4|ECC_SM4|ECDHE_SM4)"

# Erstelle Test-Zertifikate für SM2
echo "Erstelle SM2 Test-Zertifikate..."
openssl genpkey -algorithm SM2 -out sm2-key.pem
openssl req -new -key sm2-key.pem -out sm2-csr.pem -subj "/CN=SM2 Test"
openssl x509 -req -in sm2-csr.pem -signkey sm2-key.pem -out sm2-cert.pem

echo "✅ TLCP/TLS Konfiguration abgeschlossen"
