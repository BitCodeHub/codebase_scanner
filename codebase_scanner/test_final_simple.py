#\!/usr/bin/env python3
import requests
import time

print("🧪 Simple Scanner Test")
print("=" * 40)

# Create test file
code = '''
API_KEY = "sk-123456"
password = "admin123"
'''

with open('simple_test.py', 'w') as f:
    f.write(code)

# Upload
print("📤 Uploading file...")
with open('simple_test.py', 'rb') as f:
    response = requests.post(
        "https://codebase-scanner-backend-docker.onrender.com/api/scans/upload-universal",
        files={'file': ('simple_test.py', f, 'text/x-python')},
        data={'enable_ai_analysis': 'true', 'scan_type': 'comprehensive'}
    )

if response.status_code == 200:
    scan_id = response.json()['scan_id']
    print(f"✅ Scan ID: {scan_id}")
    
    # Wait and check
    print("⏳ Waiting 20 seconds...")
    time.sleep(20)
    
    # Get results
    r = requests.get(f"https://codebase-scanner-backend-docker.onrender.com/api/scans/upload-universal/{scan_id}/results")
    if r.status_code == 200:
        results = r.json()
        print(f"\n✅ RESULTS:")
        print(f"   Status: {results.get('status', 'unknown')}")
        print(f"   Files: {results.get('files_scanned', 0)}")
        print(f"   Findings: {results.get('total_findings', 0)}")
        print(f"   Secrets: {results.get('secrets', {}).get('secrets_found', 0)}")
        
        # AI status
        ai = results.get('ai_analysis', {})
        if ai.get('success'):
            print(f"\n🤖 AI Analysis: SUCCESS")
            print(f"   Tokens used: {ai.get('tokens_used', 'unknown')}")
        else:
            print(f"\n⚠️ AI Analysis: {ai.get('error', 'Not available')}")
    else:
        print(f"❌ Results error: {r.status_code}")
        print(r.text)

# Cleanup
import os
os.remove('simple_test.py')
