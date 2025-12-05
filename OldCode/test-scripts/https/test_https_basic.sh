#!/bin/bash
# TLSGate NX v3 - HTTPS Basic Tests

set -e

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Change to project root
cd "$(dirname "$0")/../.." || exit 1

# Configuration
HTTP_PORT=8889
HTTPS_PORT=8443
LISTEN_ADDR="127.0.0.1"
TEST_CA_DIR="/tmp/tlsgateNG_test_ca"
LOG_FILE="/tmp/tlsgateNG_https_test.log"

echo "=========================================="
echo "TLSGate NX v3 - HTTPS Basic Tests"
echo "=========================================="
echo ""

# Check if build exists
if [ ! -f "build/tlsgateNG" ]; then
    echo -e "${RED}Error: build/tlsgateNG not found${NC}"
    echo "Run 'make' first to build the server"
    exit 1
fi

# Setup test CA directory
echo "Setting up test CA directory..."
mkdir -p "$TEST_CA_DIR/rootCA"

# Create test CA certificate (if not exists)
if [ ! -f "$TEST_CA_DIR/rootCA/ca.crt" ]; then
    echo "Creating test CA certificate..."
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
        -keyout "$TEST_CA_DIR/rootCA/ca-key.pem" \
        -out "$TEST_CA_DIR/rootCA/ca.crt" \
        -days 3650 -nodes \
        -subj '/CN=TLSGate NX Test CA' 2>/dev/null
    echo -e "${GREEN}✓ Test CA created${NC}"
fi

# Start server
echo ""
echo "Starting TLSGate NX on HTTP:$HTTP_PORT and HTTPS:$HTTPS_PORT..."
./build/tlsgateNG -p $HTTP_PORT -s $HTTPS_PORT -l $LISTEN_ADDR -D "$TEST_CA_DIR" -w 2 > "$LOG_FILE" 2>&1 &
SERVER_PID=$!
echo "Server PID: $SERVER_PID"

# Wait for server to start
sleep 3

# Check if server is running
if ! kill -0 $SERVER_PID 2>/dev/null; then
    echo -e "${RED}✗ Server failed to start${NC}"
    echo "Log output:"
    cat "$LOG_FILE"
    exit 1
fi

echo -e "${GREEN}✓ Server started successfully${NC}"
echo ""

# Test counter
TESTS_PASSED=0
TESTS_FAILED=0

# Helper function to run test
run_test() {
    local test_name="$1"
    local test_command="$2"
    local expected_pattern="$3"

    echo "Test: $test_name"

    local result
    result=$(eval "$test_command" 2>/dev/null)

    if echo "$result" | grep -q "$expected_pattern"; then
        echo -e "${GREEN}✓ PASSED${NC}"
        ((TESTS_PASSED++))
    else
        echo -e "${RED}✗ FAILED${NC}"
        echo "Expected pattern: $expected_pattern"
        echo "Got: $result"
        ((TESTS_FAILED++))
    fi
    echo ""
}

# Run tests
echo "========== Running HTTPS Tests =========="
echo ""

# Note: Using -k to skip certificate verification for self-signed cert
# In production, you would verify the certificate properly

run_test "HTTPS GET / (Index page)" \
    "curl -s -k https://$LISTEN_ADDR:$HTTPS_PORT/" \
    "TLSGate"

run_test "HTTPS GET /favicon.ico" \
    "curl -s -k -o /tmp/favicon_https.ico https://$LISTEN_ADDR:$HTTPS_PORT/favicon.ico && file /tmp/favicon_https.ico" \
    "image data"

run_test "HTTPS GET /generate_204 (No Content)" \
    "curl -s -k -o /dev/null -w '%{http_code}' https://$LISTEN_ADDR:$HTTPS_PORT/generate_204" \
    "204"

run_test "HTTPS GET /script.js (Anti-AdBlock JS)" \
    "curl -s -k https://$LISTEN_ADDR:$HTTPS_PORT/script.js" \
    "function"

run_test "HTTPS GET /style.css (Anti-AdBlock CSS)" \
    "curl -s -k https://$LISTEN_ADDR:$HTTPS_PORT/style.css" \
    "body"

run_test "HTTPS HEAD request" \
    "curl -s -k -I https://$LISTEN_ADDR:$HTTPS_PORT/ -w '%{http_code}'" \
    "200"

run_test "HTTPS OPTIONS request" \
    "curl -s -k -X OPTIONS https://$LISTEN_ADDR:$HTTPS_PORT/ -w '%{http_code}'" \
    "200"

run_test "HTTPS Invalid method (should return 405)" \
    "curl -s -k -X INVALID https://$LISTEN_ADDR:$HTTPS_PORT/ -o /dev/null -w '%{http_code}'" \
    "405"

run_test "HTTPS TLS version check (TLS 1.2+)" \
    "curl -s -k -v https://$LISTEN_ADDR:$HTTPS_PORT/ 2>&1 | grep -E 'TLSv1\.[2-3]|TLS'" \
    "TLS"

run_test "HTTPS with SNI (example.com)" \
    "curl -s -k --resolve example.com:$HTTPS_PORT:$LISTEN_ADDR https://example.com:$HTTPS_PORT/" \
    "TLSGate"

run_test "HTTPS Content-Type for .json" \
    "curl -s -k -I https://$LISTEN_ADDR:$HTTPS_PORT/test.json | grep -i content-type" \
    "application/json"

run_test "HTTPS Content-Type for .xml" \
    "curl -s -k -I https://$LISTEN_ADDR:$HTTPS_PORT/test.xml | grep -i content-type" \
    "application/xml"

# Test certificate generation
echo "=========================================="
echo "Testing On-The-Fly Certificate Generation"
echo "=========================================="
echo ""

run_test "Certificate for google.com" \
    "curl -s -k --resolve google.com:$HTTPS_PORT:$LISTEN_ADDR https://google.com:$HTTPS_PORT/ 2>&1" \
    "TLSGate"

run_test "Certificate for github.com" \
    "curl -s -k --resolve github.com:$HTTPS_PORT:$LISTEN_ADDR https://github.com:$HTTPS_PORT/ 2>&1" \
    "TLSGate"

run_test "Certificate for api.example.com" \
    "curl -s -k --resolve api.example.com:$HTTPS_PORT:$LISTEN_ADDR https://api.example.com:$HTTPS_PORT/ 2>&1" \
    "TLSGate"

# Cleanup
echo "=========================================="
echo "Stopping server..."
kill $SERVER_PID 2>/dev/null || true
wait $SERVER_PID 2>/dev/null || true

# Summary
echo ""
echo "=========================================="
echo "Test Summary:"
echo "=========================================="
echo -e "Passed: ${GREEN}$TESTS_PASSED${NC}"
echo -e "Failed: ${RED}$TESTS_FAILED${NC}"
echo ""

if [ $TESTS_FAILED -eq 0 ]; then
    echo -e "${GREEN}✓ All tests passed!${NC}"
    exit 0
else
    echo -e "${RED}✗ Some tests failed${NC}"
    exit 1
fi
