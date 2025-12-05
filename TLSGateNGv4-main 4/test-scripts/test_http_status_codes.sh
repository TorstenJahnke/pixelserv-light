#!/bin/bash
# Test all HTTP status code implementations

echo "Starting server..."
./build/http_responder_mt 8888 127.0.0.1 -w 2 >/dev/null 2>&1 &
SERVER_PID=$!
sleep 2

echo "========================================="
echo "Test 1: OPTIONS (CORS preflight)"
echo "========================================="
curl -s -i -X OPTIONS http://127.0.0.1:8888/api/data | head -12
echo ""

echo "========================================="
echo "Test 2: 400 Bad Request (malformed)"
echo "========================================="
printf "GETPOST /test HTTP/1.1\r\n\r\n" | nc 127.0.0.1 8888 | head -6
echo ""

echo "========================================="
echo "Test 3: 414 URI Too Long (>8KB)"
echo "========================================="
LONG_URL=$(python3 -c "print('/' + 'a' * 9000)")
curl -s -i "http://127.0.0.1:8888${LONG_URL}" 2>/dev/null | head -6
echo ""

echo "========================================="
echo "Test 4: 431 Header Too Large (>16KB)"
echo "========================================="
HUGE_HEADER=$(python3 -c "print('X-Large: ' + 'x' * 17000)")
curl -s -i -H "${HUGE_HEADER}" http://127.0.0.1:8888/ 2>/dev/null | head -6
echo ""

echo "========================================="
echo "Test 5: 405 Method Not Allowed (INVALID)"
echo "========================================="
curl -s -i -X INVALID http://127.0.0.1:8888/ | head -6
echo ""

echo "========================================="
echo "Test 6: 200 OK (normal GET)"
echo "========================================="
curl -s -i http://127.0.0.1:8888/ | head -8
echo ""

kill -9 $SERVER_PID 2>/dev/null
echo "✅ All HTTP status codes tested!"
