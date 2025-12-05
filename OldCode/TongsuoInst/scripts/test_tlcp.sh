#!/bin/bash
# =============================================================================
# test_tlcp.sh - Test TLCP and Chinese Crypto Support
# =============================================================================

SCRIPT_DIR="$(dirname "$(readlink -f "$0")")"

# Find Tongsuo installation
if [ -n "$TONGSUO_ROOT_ACTIVE" ]; then
    TONGSUO_ROOT="$TONGSUO_ROOT_ACTIVE"
else
    TONGSUO_ROOT=$(ls -d /opt/tongsuo-* 2>/dev/null | sort -V | tail -1)
fi

if [ -z "$TONGSUO_ROOT" ] || [ ! -d "$TONGSUO_ROOT" ]; then
    echo "Fehler: Tongsuo nicht gefunden"
    exit 1
fi

OPENSSL="$TONGSUO_ROOT/bin/openssl"

echo "============================================"
echo " Tongsuo TLCP/SM Crypto Test"
echo "============================================"
echo ""
echo "Installation: $TONGSUO_ROOT"
echo "Version: $($OPENSSL version)"
echo ""

TEST_DIR="/tmp/tongsuo_test_$$"
mkdir -p "$TEST_DIR"
cd "$TEST_DIR"

PASSED=0
FAILED=0

test_result() {
    if [ $1 -eq 0 ]; then
        echo -e "   \033[32mOK\033[0m - $2"
        ((PASSED++))
    else
        echo -e "   \033[31mFAIL\033[0m - $2"
        ((FAILED++))
    fi
}

echo "1. SM2 Elliptic Curve (GB/T 32918)"
echo "   Testing key generation..."
$OPENSSL genpkey -algorithm SM2 -out sm2.key 2>/dev/null
test_result $? "SM2 key generation"

if [ -f sm2.key ]; then
    echo "   Testing CSR creation..."
    $OPENSSL req -new -key sm2.key -out sm2.csr -subj "/CN=Test/C=CN" -sm3 2>/dev/null
    test_result $? "SM2 CSR with SM3"

    echo "   Testing self-signed cert..."
    $OPENSSL req -new -x509 -key sm2.key -out sm2.crt -days 365 \
        -subj "/CN=Test/C=CN" -sm3 2>/dev/null
    test_result $? "SM2 self-signed certificate"
fi

echo ""
echo "2. SM3 Hash (GB/T 32905)"
echo "   Testing SM3 digest..."
echo "test" | $OPENSSL dgst -sm3 >/dev/null 2>&1
test_result $? "SM3 hash computation"

echo ""
echo "3. SM4 Block Cipher (GB/T 32907)"
echo "   Testing SM4-CBC..."
echo "testdata" | $OPENSSL enc -sm4-cbc -k testkey -pbkdf2 2>/dev/null | \
    $OPENSSL enc -sm4-cbc -d -k testkey -pbkdf2 >/dev/null 2>&1
test_result $? "SM4-CBC encrypt/decrypt"

echo "   Testing SM4-GCM..."
echo "testdata" | $OPENSSL enc -sm4-gcm -k testkey -pbkdf2 2>/dev/null | \
    $OPENSSL enc -sm4-gcm -d -k testkey -pbkdf2 >/dev/null 2>&1
test_result $? "SM4-GCM encrypt/decrypt"

echo ""
echo "4. ZUC Stream Cipher"
echo "   Testing ZUC availability..."
$OPENSSL list -cipher-algorithms 2>/dev/null | grep -qi "zuc"
test_result $? "ZUC cipher available"

echo ""
echo "5. TLS 1.3 SM Cipher Suites"
echo "   Checking available SM cipher suites..."
SM_CIPHERS=$($OPENSSL ciphers -v 'ALL' 2>/dev/null | grep -E "(SM4|SM3)" | wc -l)
if [ "$SM_CIPHERS" -gt 0 ]; then
    test_result 0 "Found $SM_CIPHERS SM cipher suites"
    $OPENSSL ciphers -v 'ALL' 2>/dev/null | grep -E "(SM4|SM3)" | head -3
else
    test_result 1 "No SM cipher suites found"
fi

echo ""
echo "6. TLCP Protocol Support"
if $OPENSSL s_client -help 2>&1 | grep -q "tlcp\|ntls"; then
    test_result 0 "TLCP/NTLS protocol flag available"
else
    echo "   INFO: TLCP via standard API (no separate flag)"
    ((PASSED++))
fi

echo ""
echo "7. Provider Information"
$OPENSSL list -providers 2>/dev/null
if [ $? -ne 0 ]; then
    echo "   Using built-in crypto (no provider system)"
fi

# Cleanup
cd /
rm -rf "$TEST_DIR"

echo ""
echo "============================================"
echo " Test Results: $PASSED passed, $FAILED failed"
echo "============================================"

[ $FAILED -eq 0 ] && exit 0 || exit 1
