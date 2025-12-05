#!/bin/bash
# Test script for http_responder

# Change to TLSGateNX2 directory if not already there
cd "$(dirname "$0")/.." || exit 1

echo "Starting HTTP Responder on port 9090..."
./build/http_responder 9090 127.0.0.1 > /tmp/server.log 2>&1 &
SERVER_PID=$!
echo "Server PID: $SERVER_PID"
sleep 2

echo ""
echo "========== TEST 1: Root (/) =========="
curl -s http://127.0.0.1:9090/ | grep -E "TLSGate|Zeit"

echo ""
echo "========== TEST 2: /favicon.ico (Real favicon - 9,462 bytes) =========="
curl -s -o /tmp/favicon.ico http://127.0.0.1:9090/favicon.ico
file /tmp/favicon.ico
SIZE=$(stat -f%z /tmp/favicon.ico 2>/dev/null || stat -c%s /tmp/favicon.ico)
echo "Size: $SIZE bytes"
if [ "$SIZE" = "9462" ]; then
  echo "✅ Correct size (9,462 bytes)"
else
  echo "❌ Wrong size! Expected 9,462 bytes, got $SIZE"
fi

echo ""
echo "========== TEST 2b: Other .ico files (httpnull_ico - 70 bytes) =========="
curl -s -o /tmp/test.ico http://127.0.0.1:9090/test.ico
SIZE=$(stat -f%z /tmp/test.ico 2>/dev/null || stat -c%s /tmp/test.ico)
echo "Size: $SIZE bytes"
if [ "$SIZE" = "70" ]; then
  echo "✅ Correct size (70 bytes - httpnull_ico)"
else
  echo "❌ Wrong size! Expected 70 bytes, got $SIZE"
fi

echo ""
echo "========== TEST 3: JavaScript (Anti-AdBlock) =========="
curl -s http://127.0.0.1:9090/script.js

echo ""
echo "========== TEST 4: CSS (Anti-AdBlock) =========="
curl -s http://127.0.0.1:9090/style.css

echo ""
echo "========== TEST 5: generate_204 =========="
curl -s -i http://127.0.0.1:9090/generate_204 | head -6

echo ""
echo "========== TEST 6: MIME Types & Security Headers =========="
echo "XML:"
curl -s -i http://127.0.0.1:9090/test.xml | grep -E "Content-Type|Access-Control"
echo "JSON:"
curl -s -i http://127.0.0.1:9090/test.json | grep -E "Content-Type|Access-Control"
echo "PNG:"
curl -s -i http://127.0.0.1:9090/test.png | grep -E "Content-Type|Access-Control"

echo ""
echo "Stopping server..."
kill $SERVER_PID 2>/dev/null
wait $SERVER_PID 2>/dev/null

echo ""
echo "✅ ALLE TESTS ABGESCHLOSSEN"
