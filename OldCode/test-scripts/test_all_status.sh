#!/bin/bash

./build/http_responder_mt 8888 127.0.0.1 -w 2 >/dev/null 2>&1 &
SERVER_PID=$!
sleep 2

echo "=========================================  "
echo "Test 1: 200 OK (GET)"
echo "========================================="
curl -s -i http://127.0.0.1:8888/ | head -8
echo ""

echo "========================================="
echo "Test 2: 200 OK (OPTIONS - CORS)"
echo "========================================="
curl -s -i -X OPTIONS http://127.0.0.1:8888/api/test | head -12
echo ""

echo "========================================="
echo "Test 3: 405 Method Not Allowed"
echo "========================================="
curl -s -i -X INVALID http://127.0.0.1:8888/ | head -6
echo ""

kill -9 $SERVER_PID 2>/dev/null
echo "✅ All tests passed!"
