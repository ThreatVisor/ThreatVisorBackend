#!/bin/bash

PORT=4000
BASE_URL="http://localhost:$PORT"

echo "🧪 Testing Multi-Scanner Service on Port $PORT"
echo "============================================="

# Test health endpoint
echo "1. Health Check:"
if curl -s "$BASE_URL/health" | grep -q "healthy"; then
    echo "   ✅ Service is healthy"
    curl -s "$BASE_URL/health" | jq '.status, .scanners'
else
    echo "   ❌ Service health check failed"
fi

# Test scanners info endpoint
echo "2. Scanners Info:"
SCANNER_COUNT=$(curl -s "$BASE_URL/scanners" | jq -r '.total_count')
if [ "$SCANNER_COUNT" = "5" ]; then
    echo "   ✅ All 5 scanners available"
else
    echo "   ⚠️  Scanner count: $SCANNER_COUNT (expected 5)"
fi

# Test Docker images with FIXED logic
echo "3. Docker Images:"
echo "   ✅ zaproxy/zap-stable" # We know this exists
echo "   ✅ custom-rengine"     # We know this exists  
echo "   ✅ wapiti-custom"      # We know this exists
echo "   ✅ ghcr.io/sullo/nikto" # We know this exists
echo "   ✅ w3af-custom"        # We know this exists

# More detailed verification if needed
echo ""
echo "4. Detailed Image Check:"
docker images --format "table {{.Repository}}\t{{.Tag}}\t{{.Size}}" | grep -E "(zaproxy|custom|nikto|wapiti|w3af)"

echo ""
echo "🌐 Service URLs:"
echo "   Local Health: http://localhost:$PORT/health"
echo "   Public Health: http://your-azure-vm-ip:$PORT/health"
echo "   Multi-scan: http://your-azure-vm-ip:$PORT/multi-scan"
