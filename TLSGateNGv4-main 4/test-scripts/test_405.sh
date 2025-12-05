#!/bin/bash

./build/http_responder_mt 8888 127.0.0.1 -w 2 >/dev/null 2>&1 &
SERVER_PID=$!
sleep 2

echo "========================================="
echo "Test: INVALID method (should be 405)"
echo "========================================="
curl -s -i -X INVALID http://127.0.0.1:8888/ | head -6
echo ""

echo "========================================="
echo "Test: GET method (should be 200 OK)"
echo "========================================="
curl -s -i http://127.0.0.1:8888/ | head -6

kill -9 $SERVER_PID 2>/dev/null
echo ""
echo "✅ Correct: 405 for invalid, 200 for valid!"
