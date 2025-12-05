# TLSGate NX v3 - Test Suite

## Overview

This directory contains automated tests for TLSGate NX v3, covering both HTTP and HTTPS functionality.

## Test Structure

```
tests/
├── http/                        # HTTP tests
│   └── test_http_basic.sh      # Basic HTTP functionality tests
├── https/                       # HTTPS tests
│   └── test_https_basic.sh     # Basic HTTPS functionality tests
└── run_all_tests.sh            # Master test runner
```

## Prerequisites

- Built `tlsgateNG` binary (`make` or `make all`)
- `curl` command-line tool
- `openssl` for certificate generation
- Basic Unix tools (file, stat, etc.)

## Running Tests

### Run All Tests

```bash
./tests/run_all_tests.sh
```

### Run HTTP Tests Only

```bash
./tests/http/test_http_basic.sh
```

### Run HTTPS Tests Only

```bash
./tests/https/test_https_basic.sh
```

## Test Coverage

### HTTP Tests

- ✓ GET / (Index page)
- ✓ GET /favicon.ico
- ✓ GET /generate_204 (No Content)
- ✓ GET /script.js (Anti-AdBlock JavaScript)
- ✓ GET /style.css (Anti-AdBlock CSS)
- ✓ HEAD request
- ✓ OPTIONS request
- ✓ Invalid method (405 response)
- ✓ Content-Type headers (.json, .xml)

### HTTPS Tests

- ✓ HTTPS GET / (Index page)
- ✓ HTTPS GET /favicon.ico
- ✓ HTTPS GET /generate_204 (No Content)
- ✓ HTTPS GET /script.js
- ✓ HTTPS GET /style.css
- ✓ HTTPS HEAD request
- ✓ HTTPS OPTIONS request
- ✓ HTTPS Invalid method (405)
- ✓ TLS version check (TLS 1.2+)
- ✓ SNI (Server Name Indication) support
- ✓ On-the-fly certificate generation for different domains
- ✓ Content-Type headers over HTTPS

## Test CA Certificate

Tests automatically create a self-signed CA certificate in `/tmp/tlsgateNG_test_ca/rootCA/`:
- `ca.crt` - Test CA certificate
- `ca-key.pem` - Test CA private key

This CA is used for on-the-fly certificate generation during HTTPS tests.

## Exit Codes

- `0` - All tests passed
- `1` - One or more tests failed

## Logs

Test logs are written to:
- HTTP tests: `/tmp/tlsgateNG_http_test.log`
- HTTPS tests: `/tmp/tlsgateNG_https_test.log`

## CI/CD Integration

These tests can be integrated into CI/CD pipelines:

```bash
# Build and test
make clean
make
./tests/run_all_tests.sh
```

## Troubleshooting

### Server fails to start

Check the log file for errors:
```bash
cat /tmp/tlsgateNG_http_test.log  # or tlsgateNG_https_test.log
```

### Certificate errors

Remove old test CA and let tests recreate it:
```bash
rm -rf /tmp/tlsgateNG_test_ca
```

### Port already in use

Tests use ports 8888 (HTTP) and 8443 (HTTPS). Ensure these ports are available:
```bash
lsof -i :8888
lsof -i :8443
```

## Adding New Tests

To add new tests:

1. Add test cases to the appropriate script (http/test_http_basic.sh or https/test_https_basic.sh)
2. Use the `run_test` helper function:

```bash
run_test "Test description" \
    "curl command" \
    "expected pattern"
```

Example:
```bash
run_test "GET /api/status returns JSON" \
    "curl -s http://127.0.0.1:8888/api/status" \
    '"status":"ok"'
```
