#!/usr/bin/env python3
"""
Quick test script for the Codebase Scanner API
"""
import requests
import json

BASE_URL = "http://localhost:8000"

def test_api():
    print("🔍 Testing Codebase Scanner API...\n")
    
    # 1. Test health endpoint
    print("1. Testing health endpoint...")
    resp = requests.get(f"{BASE_URL}/health")
    print(f"   Status: {resp.status_code}")
    print(f"   Response: {resp.json()}\n")
    
    # 2. Test API endpoint
    print("2. Testing API test endpoint...")
    resp = requests.get(f"{BASE_URL}/api/test")
    print(f"   Status: {resp.status_code}")
    print(f"   Response: {resp.json()}\n")
    
    # 3. Get available endpoints
    print("3. Available endpoints:")
    resp = requests.get(f"{BASE_URL}/openapi.json")
    if resp.status_code == 200:
        openapi = resp.json()
        for path in openapi.get("paths", {}).keys():
            print(f"   - {path}")
    print()
    
    print("✅ Basic API tests completed!")
    print("\n📝 Next steps:")
    print("1. Open the frontend at http://localhost:5174")
    print("2. Use the 'Run Quick Scan' feature to upload and scan a file")
    print("3. Or use the API docs at http://localhost:8000/docs")

if __name__ == "__main__":
    test_api()