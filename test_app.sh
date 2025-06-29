#!/bin/bash

# Codebase Scanner Test Script
# This script helps test the application functionality

set -e

echo "=== Codebase Scanner Test Script ==="
echo

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
API_URL="http://localhost:8000"
FRONTEND_URL="http://localhost:5173"
TEST_USER="testuser_$(date +%s)"
TEST_EMAIL="${TEST_USER}@example.com"
TEST_PASSWORD="TestPass123!"

# Function to check if services are running
check_services() {
    echo "Checking services..."
    
    # Check if docker-compose is running
    if ! docker-compose ps | grep -q "Up"; then
        echo -e "${RED}Error: Services are not running. Starting them now...${NC}"
        docker-compose up -d
        echo "Waiting for services to start (30 seconds)..."
        sleep 30
    fi
    
    # Check backend
    if curl -s -o /dev/null -w "%{http_code}" "$API_URL/health" | grep -q "200"; then
        echo -e "${GREEN}✓ Backend is running${NC}"
    else
        echo -e "${RED}✗ Backend is not responding${NC}"
        exit 1
    fi
    
    # Check frontend
    if curl -s -o /dev/null -w "%{http_code}" "$FRONTEND_URL" | grep -q "200"; then
        echo -e "${GREEN}✓ Frontend is running${NC}"
    else
        echo -e "${RED}✗ Frontend is not responding${NC}"
        exit 1
    fi
    
    echo
}

# Function to register a test user
register_user() {
    echo "Registering test user..."
    
    REGISTER_RESPONSE=$(curl -s -X POST "$API_URL/api/auth/register" \
        -H "Content-Type: application/json" \
        -d "{
            \"email\": \"$TEST_EMAIL\",
            \"username\": \"$TEST_USER\",
            \"password\": \"$TEST_PASSWORD\",
            \"full_name\": \"Test User\"
        }")
    
    if echo "$REGISTER_RESPONSE" | grep -q "id"; then
        echo -e "${GREEN}✓ User registered successfully${NC}"
        echo "  Username: $TEST_USER"
        echo "  Email: $TEST_EMAIL"
    else
        echo -e "${RED}✗ Failed to register user${NC}"
        echo "Response: $REGISTER_RESPONSE"
        exit 1
    fi
    
    echo
}

# Function to login and get token
login_user() {
    echo "Logging in..."
    
    LOGIN_RESPONSE=$(curl -s -X POST "$API_URL/api/auth/token" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "username=$TEST_USER&password=$TEST_PASSWORD")
    
    TOKEN=$(echo "$LOGIN_RESPONSE" | grep -o '"access_token":"[^"]*' | cut -d'"' -f4)
    
    if [ -n "$TOKEN" ]; then
        echo -e "${GREEN}✓ Login successful${NC}"
        export AUTH_TOKEN="$TOKEN"
    else
        echo -e "${RED}✗ Login failed${NC}"
        echo "Response: $LOGIN_RESPONSE"
        exit 1
    fi
    
    echo
}

# Function to create a test project
create_project() {
    echo "Creating test project..."
    
    PROJECT_RESPONSE=$(curl -s -X POST "$API_URL/api/projects" \
        -H "Authorization: Bearer $AUTH_TOKEN" \
        -H "Content-Type: application/json" \
        -d '{
            "name": "Test Security Project",
            "description": "Automated test project",
            "github_repo_url": "https://github.com/OWASP/NodeGoat",
            "scan_config": {
                "enable_static_analysis": true,
                "enable_ai_analysis": true
            }
        }')
    
    PROJECT_ID=$(echo "$PROJECT_RESPONSE" | grep -o '"id":[0-9]*' | cut -d: -f2)
    
    if [ -n "$PROJECT_ID" ]; then
        echo -e "${GREEN}✓ Project created successfully (ID: $PROJECT_ID)${NC}"
        export TEST_PROJECT_ID="$PROJECT_ID"
    else
        echo -e "${RED}✗ Failed to create project${NC}"
        echo "Response: $PROJECT_RESPONSE"
        exit 1
    fi
    
    echo
}

# Function to create vulnerable test files
create_test_files() {
    echo "Creating vulnerable test files..."
    
    mkdir -p test_code
    
    # Vulnerable Python file
    cat > test_code/vulnerable.py << 'EOF'
import os
import sqlite3

def unsafe_query(user_id):
    conn = sqlite3.connect('users.db')
    # SQL Injection vulnerability
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return conn.execute(query).fetchall()

def unsafe_command(host):
    # Command injection vulnerability
    os.system(f"ping -c 1 {host}")

# Hardcoded credentials
API_KEY = "sk-1234567890abcdef"
PASSWORD = "admin123"
EOF

    # Vulnerable JavaScript file
    cat > test_code/vulnerable.js << 'EOF'
const express = require('express');
const app = express();

// XSS vulnerability
app.get('/search', (req, res) => {
    const query = req.query.q;
    res.send(`<h1>Results for: ${query}</h1>`);
});

// Hardcoded secret
const JWT_SECRET = 'my-secret-key';
EOF

    # Create ZIP file
    cd test_code && zip -r ../test_code.zip . && cd ..
    
    echo -e "${GREEN}✓ Test files created${NC}"
    echo
}

# Function to upload test code
upload_code() {
    echo "Uploading test code..."
    
    UPLOAD_RESPONSE=$(curl -s -X POST "$API_URL/api/projects/$TEST_PROJECT_ID/upload" \
        -H "Authorization: Bearer $AUTH_TOKEN" \
        -F "file=@test_code.zip")
    
    if echo "$UPLOAD_RESPONSE" | grep -q "success"; then
        echo -e "${GREEN}✓ Code uploaded successfully${NC}"
    else
        echo -e "${YELLOW}⚠ Upload may have failed (testing with GitHub URL instead)${NC}"
    fi
    
    # Cleanup
    rm -rf test_code test_code.zip
    
    echo
}

# Function to start a scan
start_scan() {
    echo "Starting security scan..."
    
    SCAN_RESPONSE=$(curl -s -X POST "$API_URL/api/scans" \
        -H "Authorization: Bearer $AUTH_TOKEN" \
        -H "Content-Type: application/json" \
        -d "{
            \"project_id\": $TEST_PROJECT_ID,
            \"scan_type\": \"security\"
        }")
    
    SCAN_ID=$(echo "$SCAN_RESPONSE" | grep -o '"id":[0-9]*' | cut -d: -f2)
    
    if [ -n "$SCAN_ID" ]; then
        echo -e "${GREEN}✓ Scan started successfully (ID: $SCAN_ID)${NC}"
        export TEST_SCAN_ID="$SCAN_ID"
    else
        echo -e "${RED}✗ Failed to start scan${NC}"
        echo "Response: $SCAN_RESPONSE"
        exit 1
    fi
    
    echo
}

# Function to check scan status
check_scan_status() {
    echo "Checking scan status..."
    
    for i in {1..30}; do
        SCAN_STATUS=$(curl -s -X GET "$API_URL/api/scans/$TEST_SCAN_ID" \
            -H "Authorization: Bearer $AUTH_TOKEN")
        
        STATUS=$(echo "$SCAN_STATUS" | grep -o '"status":"[^"]*' | cut -d'"' -f4)
        
        case "$STATUS" in
            "completed")
                echo -e "${GREEN}✓ Scan completed successfully${NC}"
                
                # Get issue counts
                TOTAL=$(echo "$SCAN_STATUS" | grep -o '"total_issues":[0-9]*' | cut -d: -f2)
                CRITICAL=$(echo "$SCAN_STATUS" | grep -o '"critical_issues":[0-9]*' | cut -d: -f2)
                HIGH=$(echo "$SCAN_STATUS" | grep -o '"high_issues":[0-9]*' | cut -d: -f2)
                
                echo "  Total issues: $TOTAL"
                echo "  Critical: $CRITICAL"
                echo "  High: $HIGH"
                return 0
                ;;
            "failed")
                echo -e "${RED}✗ Scan failed${NC}"
                echo "Response: $SCAN_STATUS"
                return 1
                ;;
            "running"|"pending")
                echo -ne "\r  Status: $STATUS (${i}/30)..."
                sleep 2
                ;;
            *)
                echo -e "${YELLOW}⚠ Unknown status: $STATUS${NC}"
                sleep 2
                ;;
        esac
    done
    
    echo -e "${YELLOW}⚠ Scan timeout - may still be running${NC}"
    echo
}

# Function to get scan results
get_scan_results() {
    echo "Getting scan results..."
    
    RESULTS=$(curl -s -X GET "$API_URL/api/scans/$TEST_SCAN_ID/results?limit=5" \
        -H "Authorization: Bearer $AUTH_TOKEN")
    
    if echo "$RESULTS" | grep -q "title"; then
        echo -e "${GREEN}✓ Retrieved scan results${NC}"
        echo "$RESULTS" | python3 -m json.tool | head -50
    else
        echo -e "${YELLOW}⚠ No results found${NC}"
    fi
    
    echo
}

# Function to generate report
generate_report() {
    echo "Generating security report..."
    
    REPORT_RESPONSE=$(curl -s -X POST "$API_URL/api/reports" \
        -H "Authorization: Bearer $AUTH_TOKEN" \
        -H "Content-Type: application/json" \
        -d "{
            \"scan_id\": $TEST_SCAN_ID,
            \"report_type\": \"security\",
            \"format\": \"json\"
        }")
    
    REPORT_ID=$(echo "$REPORT_RESPONSE" | grep -o '"id":[0-9]*' | cut -d: -f2)
    
    if [ -n "$REPORT_ID" ]; then
        echo -e "${GREEN}✓ Report generated successfully (ID: $REPORT_ID)${NC}"
        
        # Check launch ready status
        LAUNCH_READY=$(echo "$REPORT_RESPONSE" | grep -o '"launch_ready":[^,]*' | cut -d: -f2)
        SCORE=$(echo "$REPORT_RESPONSE" | grep -o '"security_score":[0-9]*' | cut -d: -f2)
        
        echo "  Launch Ready: $LAUNCH_READY"
        echo "  Security Score: $SCORE/100"
    else
        echo -e "${YELLOW}⚠ Report generation may have failed${NC}"
    fi
    
    echo
}

# Function to test API endpoints
test_api_endpoints() {
    echo "Testing API endpoints..."
    
    # Test health endpoint
    echo -n "  Health check: "
    if curl -s "$API_URL/health" | grep -q "healthy"; then
        echo -e "${GREEN}✓${NC}"
    else
        echo -e "${RED}✗${NC}"
    fi
    
    # Test auth endpoint
    echo -n "  Auth check: "
    if curl -s -H "Authorization: Bearer $AUTH_TOKEN" "$API_URL/api/auth/me" | grep -q "$TEST_USER"; then
        echo -e "${GREEN}✓${NC}"
    else
        echo -e "${RED}✗${NC}"
    fi
    
    # Test projects list
    echo -n "  Projects list: "
    if curl -s -H "Authorization: Bearer $AUTH_TOKEN" "$API_URL/api/projects" | grep -q "Test Security Project"; then
        echo -e "${GREEN}✓${NC}"
    else
        echo -e "${RED}✗${NC}"
    fi
    
    echo
}

# Function to display summary
display_summary() {
    echo "=== Test Summary ==="
    echo
    echo "Test User: $TEST_USER"
    echo "Project ID: $TEST_PROJECT_ID"
    echo "Scan ID: $TEST_SCAN_ID"
    echo
    echo -e "${GREEN}All tests completed!${NC}"
    echo
    echo "You can now:"
    echo "1. Visit $FRONTEND_URL and login with:"
    echo "   Username: $TEST_USER"
    echo "   Password: $TEST_PASSWORD"
    echo
    echo "2. View API documentation at:"
    echo "   $API_URL/docs"
    echo
    echo "3. Check logs with:"
    echo "   docker-compose logs -f"
}

# Main execution
main() {
    check_services
    register_user
    login_user
    create_project
    create_test_files
    upload_code
    start_scan
    check_scan_status
    get_scan_results
    generate_report
    test_api_endpoints
    display_summary
}

# Run main function
main