#!/bin/bash
# TLSGate NX v3 - Run All Tests

set -e

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

cd "$(dirname "$0")/.." || exit 1

echo "=========================================="
echo "TLSGate NX v3 - Test Suite"
echo "=========================================="
echo ""

# Build if needed
if [ ! -f "build/tlsgateNG" ]; then
    echo "Building TLSGate NX..."
    make
    echo ""
fi

TOTAL_PASSED=0
TOTAL_FAILED=0

# Run HTTP tests
echo ""
echo "=========================================="
echo "Running HTTP Tests"
echo "=========================================="
if ./tests/http/test_http_basic.sh; then
    echo -e "${GREEN}✓ HTTP tests passed${NC}"
else
    echo -e "${RED}✗ HTTP tests failed${NC}"
    TOTAL_FAILED=$((TOTAL_FAILED + 1))
fi

# Run HTTPS tests (currently disabled - not yet implemented)
echo ""
echo "=========================================="
echo "HTTPS Tests (Skipped - Not Yet Implemented)"
echo "=========================================="
echo -e "${YELLOW}ℹ HTTPS support is under development${NC}"
echo -e "${YELLOW}ℹ Server uses HTTP/HTTPS auto-detection on single port${NC}"
echo -e "${YELLOW}ℹ See tests/https/README.md for details${NC}"

# Uncomment when HTTPS separate port support is implemented:
# if ./tests/https/test_https_basic.sh; then
#     echo -e "${GREEN}✓ HTTPS tests passed${NC}"
# else
#     echo -e "${RED}✗ HTTPS tests failed${NC}"
#     TOTAL_FAILED=$((TOTAL_FAILED + 1))
# fi

# Final summary
echo ""
echo "=========================================="
echo "Final Test Summary"
echo "=========================================="
if [ $TOTAL_FAILED -eq 0 ]; then
    echo -e "${GREEN}✓ All test suites passed!${NC}"
    exit 0
else
    echo -e "${RED}✗ $TOTAL_FAILED test suite(s) failed${NC}"
    exit 1
fi
