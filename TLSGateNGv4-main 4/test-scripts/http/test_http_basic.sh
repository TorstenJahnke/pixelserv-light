#!/bin/bash
# TLSGate NX v3 - HTTP Basic Tests

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Change to project root
cd "$(dirname "$0")/../.." || exit 1

# Configuration
HTTP_PORT=8888
LISTEN_ADDR="127.0.0.1"
TEST_CA_DIR="/tmp/tlsgateNG_test_ca"
LOG_FILE="/tmp/tlsgateNG_http_test.log"

echo "=========================================="
echo "TLSGate NX v3 - HTTP Basic Tests"
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
echo "Starting TLSGate NX on port $HTTP_PORT..."
./build/tlsgateNG -p $HTTP_PORT -l $LISTEN_ADDR -D "$TEST_CA_DIR" -w 2 > "$LOG_FILE" 2>&1 &
SERVER_PID=$!
echo "Server PID: $SERVER_PID"

# Wait for server to start
sleep 2

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
echo "========== Running HTTP Tests =========="
echo ""

run_test "GET / (Index page)" \
    "curl -s http://$LISTEN_ADDR:$HTTP_PORT/" \
    "TLSGate"

run_test "GET /favicon.ico" \
    "curl -s -o /tmp/favicon.ico http://$LISTEN_ADDR:$HTTP_PORT/favicon.ico && file /tmp/favicon.ico" \
    "icon"

run_test "GET /generate_204 (No Content)" \
    "curl -s -o /dev/null -w '%{http_code}' http://$LISTEN_ADDR:$HTTP_PORT/generate_204" \
    "204"

run_test "GET /script.js (Anti-AdBlock JS - has content)" \
    "curl -s http://$LISTEN_ADDR:$HTTP_PORT/script.js | wc -c" \
    "[1-9]"

run_test "GET /style.css (Anti-AdBlock CSS - has content)" \
    "curl -s http://$LISTEN_ADDR:$HTTP_PORT/style.css | wc -c" \
    "[1-9]"

run_test "HEAD request" \
    "curl -s -I http://$LISTEN_ADDR:$HTTP_PORT/ -w '%{http_code}'" \
    "200"

run_test "OPTIONS request" \
    "curl -s -X OPTIONS http://$LISTEN_ADDR:$HTTP_PORT/ -w '%{http_code}'" \
    "200"

run_test "Invalid method (should return 405)" \
    "curl -s -X INVALID http://$LISTEN_ADDR:$HTTP_PORT/ -o /dev/null -w '%{http_code}'" \
    "405"

run_test "Content-Type for .json" \
    "curl -s -I http://$LISTEN_ADDR:$HTTP_PORT/test.json | grep -i content-type" \
    "application/json"

run_test "Content-Type for .xml" \
    "curl -s -I http://$LISTEN_ADDR:$HTTP_PORT/test.xml | grep -i content-type" \
    "xml"

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
