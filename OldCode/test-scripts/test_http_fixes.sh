#!/bin/bash
# Comprehensive HTTP fix tests

echo "Starting server..."
./build/http_responder_mt 8080 127.0.0.1 -w 2 >/dev/null 2>&1 &
SERVER_PID=$!
sleep 2

echo "========================================="
echo "Test 1: Keep-Alive (HTTP/1.1 default)"
echo "========================================="
curl -s -i http://localhost:8080/ | head -15 | grep -E "^HTTP|^Connection:|^Content-Length:"
echo ""

echo "========================================="
echo "Test 2: HEAD request (same Content-Length as GET, no body)"
echo "========================================="
echo "GET /test.html:"
curl -s -I http://localhost:8080/test.html | grep -E "^HTTP|^Content-Length:"
echo "HEAD /test.html:"
curl -s -X HEAD -I http://localhost:8080/test.html | grep -E "^HTTP|^Content-Length:"
echo ""

echo "========================================="
echo "Test 3: Invalid HTTP method (should return 405)"
echo "========================================="
curl -s -i -X INVALID http://localhost:8080/ | head -8
echo ""

echo "========================================="
echo "Test 4: Multiple requests on same connection"
echo "========================================="
(
  printf "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"
  sleep 0.5
  printf "GET /test.js HTTP/1.1\r\nHost: localhost\r\n\r\n"
  sleep 0.5
) | nc localhost 8080 | grep -c "^HTTP/1.1 200"
echo "Expected: 2, Got: ^"
echo ""

echo "Stopping server..."
kill -9 $SERVER_PID 2>/dev/null
echo "✅ All tests complete!"
