#!/bin/bash

./build/http_responder_mt 8888 127.0.0.1 -w 2 >/dev/null 2>&1 &
SERVER_PID=$!
sleep 2

echo "Test 1: OPTIONS"
curl -s -X OPTIONS http://127.0.0.1:8888/ | head -3

echo ""
echo "Test 2: 405 INVALID"
curl -s -X INVALID http://127.0.0.1:8888/ | head -3

echo ""
echo "Test 3: 200 GET"
curl -s http://127.0.0.1:8888/ | head -3

kill -9 $SERVER_PID 2>/dev/null
