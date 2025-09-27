#!/bin/bash

PORT=4000
BASE_URL="http://localhost:$PORT"

echo "🧪 Testing Multi-Scanner Service on Port $PORT"
echo "============================================="

# Test health endpoint (without jq dependency)
echo "1. Health Check:"
HEALTH_RESPONSE=$(curl -s "$BASE_URL/health")
if echo "$HEALTH_RESPONSE" | grep -q "healthy"; then
    echo "   ✅ Service is healthy"
    echo "   Response: $HEALTH_RESPONSE"
else
    echo "   ❌ Service health check failed"
    echo "   Response: $HEALTH_RESPONSE"
fi

echo ""
echo "2. Scanners Info:"
SCANNERS_RESPONSE=$(curl -s "$BASE_URL/scanners")
echo "   Response: $SCANNERS_RESPONSE"

echo ""
echo "3. Actual Docker Images Available:"
docker images --format "table {{.Repository}}\t{{.Tag}}\t{{.Size}}" | grep -E "(zaproxy|custom|nikto|wapiti|w3af)"

echo ""
echo "4. Test Multi-scan Endpoint:"
TEST_PAYLOAD='{"target":"https://httpbin.org","scanId":"test-'$(date +%s)'","supabaseUrl":"https://test.supabase.co","supabaseKey":"test-key","scanners":["zap"],"zapOptions":{"ajaxSpider":false}}'

SCAN_RESPONSE=$(curl -s -X POST "$BASE_URL/multi-scan" \
    -H "Content-Type: application/json" \
    -d "$TEST_PAYLOAD")

if echo "$SCAN_RESPONSE" | grep -q "success"; then
    echo "   ✅ Multi-scan endpoint working"
    echo "   Response: $SCAN_RESPONSE"
else
    echo "   ⚠️  Multi-scan response: $SCAN_RESPONSE"
fi

echo ""
echo "🌐 Service URLs:"
echo "   Local Health: http://localhost:$PORT/health"
echo "   Public Health: http://your-azure-vm-ip:$PORT/health"
echo "   Multi-scan: http://your-azure-vm-ip:$PORT/multi-scan"
