#!/usr/bin/env python3
"""
Test the new GitHub scan and optimized scanner tools endpoints
"""

import requests
import json
import time
from datetime import datetime

# Configuration
BACKEND_URL = "https://codebase-scanner-backend-docker.onrender.com"
TEST_REPO = "https://github.com/Hyundai-Kia-Connect/hyundai_kia_connect_api"

def test_endpoints():
    print("🧪 Testing New Endpoints")
    print("=" * 60)
    
    # Test 1: Cached scanner tools (should be fast)
    print("\n1️⃣ Testing cached scanner tools endpoint...")
    try:
        start = time.time()
        response = requests.get(f"{BACKEND_URL}/api/test/scanner-tools-cached", timeout=5)
        elapsed = time.time() - start
        
        if response.status_code == 200:
            data = response.json()
            print(f"✅ Success in {elapsed:.2f}s")
            print(f"   Tools: {data['summary']}")
            print(f"   Status: {data['status']}")
        else:
            print(f"❌ Failed: {response.status_code}")
    except Exception as e:
        print(f"❌ Error: {e}")
    
    # Test 2: Fast scanner tools (async)
    print("\n2️⃣ Testing fast scanner tools endpoint...")
    try:
        start = time.time()
        response = requests.get(f"{BACKEND_URL}/api/test/scanner-tools-fast", timeout=10)
        elapsed = time.time() - start
        
        if response.status_code == 200:
            data = response.json()
            print(f"✅ Success in {elapsed:.2f}s")
            print(f"   Tools: {data['summary']}")
            print(f"   Status: {data['status']}")
        else:
            print(f"❌ Failed: {response.status_code}")
    except Exception as e:
        print(f"❌ Error: {e}")
    
    # Test 3: GitHub scan endpoint
    print("\n3️⃣ Testing GitHub scan endpoint...")
    try:
        scan_data = {
            "repository_url": TEST_REPO,
            "scan_type": "full",
            "enable_ai_analysis": False
        }
        
        response = requests.post(
            f"{BACKEND_URL}/api/scans/github",
            json=scan_data,
            timeout=10
        )
        
        if response.status_code == 200:
            data = response.json()
            print(f"✅ Scan initiated!")
            print(f"   Scan ID: {data['scan_id']}")
            print(f"   Status: {data['status']}")
            print(f"   Repository: {data['repository_url']}")
            
            # Check scan status
            scan_id = data['scan_id']
            print("\n   Checking scan status...")
            time.sleep(2)
            
            status_response = requests.get(
                f"{BACKEND_URL}/api/scans/github/{scan_id}/status",
                timeout=5
            )
            
            if status_response.status_code == 200:
                status_data = status_response.json()
                print(f"   Progress: {status_data.get('progress', 0)}%")
                print(f"   Status: {status_data.get('status', 'unknown')}")
        else:
            print(f"❌ Failed: {response.status_code}")
            if response.headers.get('content-type', '').startswith('application/json'):
                print(f"   Error: {response.json()}")
    except Exception as e:
        print(f"❌ Error: {e}")
    
    # Test 4: Original scanner tools endpoint (for comparison)
    print("\n4️⃣ Testing original scanner tools endpoint (may timeout)...")
    try:
        start = time.time()
        response = requests.get(f"{BACKEND_URL}/api/test/scanner-tools", timeout=15)
        elapsed = time.time() - start
        
        if response.status_code == 200:
            data = response.json()
            available = data.get('available_tools', 0)
            total = data.get('total_tools', 0)
            print(f"✅ Success in {elapsed:.2f}s")
            print(f"   Tools: {available}/{total} available")
        else:
            print(f"❌ Failed: {response.status_code}")
    except requests.exceptions.Timeout:
        print(f"⏱️  Timed out (as expected for cold start)")
    except Exception as e:
        print(f"❌ Error: {e}")
    
    print("\n" + "=" * 60)
    print("✅ Testing complete!")

if __name__ == "__main__":
    print(f"🚀 Testing backend at: {BACKEND_URL}")
    print(f"📅 Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Wait a moment for deployment to complete
    print("\n⏳ Waiting for deployment to complete...")
    time.sleep(5)
    
    test_endpoints()