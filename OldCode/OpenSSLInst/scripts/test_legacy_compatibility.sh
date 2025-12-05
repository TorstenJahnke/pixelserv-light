#!/bin/bash
# Test Legacy Compatibility
# Ausführung: /opt/openssl-3.6.0/scripts/test_legacy_compatibility.sh

source /opt/openssl-3.6.0/scripts/activate.sh

TEST_DIR="/opt/openssl-3.6.0/test"
mkdir -p "$TEST_DIR"
cd "$TEST_DIR"

echo "🧪 Legacy Compatibility Test"
echo "============================="

# RSA Tests
echo "1. 🔑 RSA Schlüssel:"
for bits in 1024 2048 4096; do
    if openssl genrsa -out "rsa_${bits}.pem" "$bits" 2>/dev/null; then
        echo "   ✅ RSA-$bits erfolgreich"
    else
        echo "   ❌ RSA-$bits fehlgeschlagen"
    fi
done

# SM Tests
echo "2. 🔐 SM Algorithmen:"
if openssl genpkey -algorithm SM2 -out "sm2.pem" 2>/dev/null; then
    echo "   ✅ SM2 erfolgreich"
else
    echo "   ❌ SM2 fehlgeschlagen"
fi

echo "test" | openssl sm3 >/dev/null 2>&1 && echo "   ✅ SM3 erfolgreich" || echo "   ❌ SM3 fehlgeschlagen"

# Legacy Ciphers
echo "3. 🔓 Legacy Ciphers:"
openssl ciphers -v 'ALL' | grep -c SSLv3 | xargs echo "   Verfügbare SSLv3 Ciphers:"

# Final Check
echo "4. ✅ Finaler Status:"
echo "   OpenSSL Version: $(openssl version)"
echo "   Library Path: $(openssl version -f | head -1)"
echo "   Providers: $(openssl list -providers | grep -c Name) aktiv"

echo "🎯 Legacy Test abgeschlossen"
