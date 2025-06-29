#!/bin/bash

echo "=== Simple API Test ==="
echo

# Test registration
echo "1. Testing user registration..."
curl -X POST http://localhost:8000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "simple@test.com",
    "username": "simpletest",
    "password": "testpass123",
    "full_name": "Simple Test"
  }'
echo
echo

# Test login  
echo "2. Testing login..."
TOKEN_RESPONSE=$(curl -s -X POST http://localhost:8000/api/auth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=simpletest&password=testpass123")

echo "Response: $TOKEN_RESPONSE"
TOKEN=$(echo "$TOKEN_RESPONSE" | grep -o '"access_token":"[^"]*' | cut -d'"' -f4)
echo "Token: $TOKEN"
echo

# Test authenticated endpoint
echo "3. Testing authenticated endpoint..."
curl -X GET http://localhost:8000/api/auth/me \
  -H "Authorization: Bearer $TOKEN"
echo
echo

# Test project creation
echo "4. Testing project creation..."
curl -X POST http://localhost:8000/api/projects \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Simple Test Project",
    "description": "Testing the API"
  }'
echo