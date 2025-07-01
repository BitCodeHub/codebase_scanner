#!/bin/bash

# Backend Test Script for Codebase Scanner
# Tests all major endpoints and functionality

BACKEND_URL="https://codebase-scanner-backend-docker.onrender.com"
# BACKEND_URL="http://localhost:8000"  # Uncomment for local testing

echo "================================================"
echo "Testing Backend: $BACKEND_URL"
echo "================================================"

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to test endpoint
test_endpoint() {
    local name=$1
    local endpoint=$2
    local method=${3:-GET}
    local data=$4
    
    echo -e "\n${YELLOW}Testing: $name${NC}"
    echo "Endpoint: $endpoint"
    
    if [ "$method" = "GET" ]; then
        response=$(curl -s -w "\nHTTP_STATUS:%{http_code}" "$BACKEND_URL$endpoint")
    else
        response=$(curl -s -X $method -H "Content-Type: application/json" -d "$data" -w "\nHTTP_STATUS:%{http_code}" "$BACKEND_URL$endpoint")
    fi
    
    http_status=$(echo "$response" | grep "HTTP_STATUS:" | cut -d: -f2)
    body=$(echo "$response" | sed '/HTTP_STATUS:/d')
    
    if [ "$http_status" = "200" ]; then
        echo -e "${GREEN}✓ Status: $http_status${NC}"
    else
        echo -e "${RED}✗ Status: $http_status${NC}"
    fi
    
    echo "Response:"
    echo "$body" | jq . 2>/dev/null || echo "$body"
}

# Test 1: Root endpoint
test_endpoint "Root Endpoint" "/"

# Test 2: Health check
test_endpoint "Health Check" "/health"

# Test 3: API test
test_endpoint "API Test" "/api/test"

# Test 4: Scanner tools
test_endpoint "Scanner Tools Status" "/api/test/scanner-tools"

# Test 5: Supabase connection
test_endpoint "Supabase Connection" "/api/supabase/test"

# Test 6: AI analysis test
test_endpoint "AI Analysis Test" "/api/test/ai-analysis" "POST" "{}"

# Test 7: API Documentation
echo -e "\n${YELLOW}Testing: API Documentation${NC}"
echo "Swagger UI: $BACKEND_URL/docs"
echo "ReDoc: $BACKEND_URL/redoc"

swagger_status=$(curl -s -o /dev/null -w "%{http_code}" "$BACKEND_URL/docs")
redoc_status=$(curl -s -o /dev/null -w "%{http_code}" "$BACKEND_URL/redoc")

if [ "$swagger_status" = "200" ]; then
    echo -e "${GREEN}✓ Swagger UI: Accessible${NC}"
else
    echo -e "${RED}✗ Swagger UI: Not accessible (Status: $swagger_status)${NC}"
fi

if [ "$redoc_status" = "200" ]; then
    echo -e "${GREEN}✓ ReDoc: Accessible${NC}"
else
    echo -e "${RED}✗ ReDoc: Not accessible (Status: $redoc_status)${NC}"
fi

# Summary
echo -e "\n================================================"
echo -e "${YELLOW}Test Summary${NC}"
echo "================================================"
echo "Backend URL: $BACKEND_URL"
echo "Test completed at: $(date)"

# Additional manual tests
echo -e "\n${YELLOW}Additional Manual Tests:${NC}"
echo "1. Test file upload scanning:"
echo "   - Use the Swagger UI at $BACKEND_URL/docs"
echo "   - Try the POST /api/scans endpoint"
echo ""
echo "2. Test repository scanning:"
echo "   - Try POST /api/scans/repository with a GitHub URL"
echo ""
echo "3. Check Render logs:"
echo "   - Visit https://dashboard.render.com"
echo "   - Check for any error messages"

# Check if all critical endpoints are working
echo -e "\n${YELLOW}Critical Systems Check:${NC}"

# Function to check critical system
check_system() {
    local name=$1
    local check_command=$2
    
    if eval "$check_command" > /dev/null 2>&1; then
        echo -e "${GREEN}✓ $name: Operational${NC}"
        return 0
    else
        echo -e "${RED}✗ $name: Not operational${NC}"
        return 1
    fi
}

# Check critical systems
check_system "API Server" "curl -s -f $BACKEND_URL/health"
check_system "Database Connection" "curl -s $BACKEND_URL/api/supabase/test | grep -q 'connected'"
check_system "Security Tools" "curl -s $BACKEND_URL/api/test/scanner-tools | grep -q 'available_tools'"
check_system "Production Environment" "curl -s $BACKEND_URL/api/test | grep -q 'production'"