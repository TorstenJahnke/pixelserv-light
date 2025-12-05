#!/bin/bash
# Test HTTP/1.1 keep-alive

echo "Starting server..."
./build/http_responder_mt 8080 127.0.0.1 -w 2 >/dev/null 2>&1 &
SERVER_PID=$!
sleep 2

echo "Testing HTTP/1.1 keep-alive (3 requests on same connection)..."
(
  printf "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"
  sleep 0.5
  printf "GET /test.html HTTP/1.1\r\nHost: localhost\r\n\r\n"
  sleep 0.5
  printf "GET /test.js HTTP/1.1\r\nHost: localhost\r\n\r\n"
  sleep 0.5
) | nc localhost 8080 | grep -E "^HTTP|^Connection:" | head -20

echo ""
echo "Stopping server..."
kill -9 $SERVER_PID 2>/dev/null
echo "Done!"
