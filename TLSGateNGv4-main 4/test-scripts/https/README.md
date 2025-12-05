# HTTPS Tests - Not Yet Implemented

## Status

HTTPS support in TLSGate NX v3 is currently under development. The server uses **auto-detection** of HTTP/HTTPS on a single port, not separate ports.

From `src/tlsgateNG.c:858-859`:
```c
/* Create listening socket (v2: auto-detect HTTP/HTTPS on same port) */
/* TODO: Implement separate HTTP and HTTPS ports like v1 */
```

## Current Behavior

- The `-s` (HTTPS port) option is accepted but not yet implemented
- HTTP and HTTPS are auto-detected on the same port (specified by `-p`)
- TLS engine is initialized, but separate HTTPS port listening is not implemented

## Future Implementation

Once separate HTTPS port support is implemented, the test script `test_https_basic.sh` will be ready to use. It includes:

- Basic HTTPS connectivity tests
- TLS version verification
- SNI (Server Name Indication) support tests
- On-the-fly certificate generation tests
- Content-Type verification over HTTPS

## Testing HTTP Only

For now, use the HTTP tests in `tests/http/` which work correctly:

```bash
./tests/http/test_http_basic.sh
```

## When HTTPS Is Ready

1. Uncomment the HTTPS test section in `tests/run_all_tests.sh`
2. Run the full test suite:
   ```bash
   ./tests/run_all_tests.sh
   ```
