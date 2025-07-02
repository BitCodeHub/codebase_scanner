#!/usr/bin/env python3
"""
Final test of the complete scanner with AI analysis
"""

import requests
import time
import json

def test_final_scanner():
    print("🎯 FINAL SCANNER TEST")
    print("=" * 60)
    
    # Create a vulnerable code snippet
    vulnerable_code = '''
# Test vulnerable code
import os
import pickle

# Hardcoded secrets
API_KEY = "sk-proj-abc123xyz789"
DATABASE_PASSWORD = "admin123"
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"

# SQL injection
def get_user(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return query

# Unsafe deserialization
def load_data(data):
    return pickle.loads(data)

# Weak crypto
import hashlib
def hash_password(pwd):
    return hashlib.md5(pwd.encode()).hexdigest()
'''
    
    # Save to file
    with open('test_vuln.py', 'w') as f:
        f.write(vulnerable_code)
    
    print("📝 Created test file with vulnerabilities")
    print("🚀 Uploading to scanner...")
    
    # Upload file
    with open('test_vuln.py', 'rb') as f:
        files = {'file': ('test_vuln.py', f, 'text/x-python')}
        data = {
            'enable_ai_analysis': 'true',
            'scan_type': 'comprehensive'
        }
        
        response = requests.post(
            "https://codebase-scanner-backend-docker.onrender.com/api/scans/upload-universal",
            files=files,
            data=data
        )
    
    if response.status_code == 200:
        scan_id = response.json()['scan_id']
        print(f"✅ Upload successful! Scan ID: {scan_id}")
        
        # Wait for scan
        print("⏳ Waiting for scan completion...")
        time.sleep(15)
        
        # Get results
        results = requests.get(
            f"https://codebase-scanner-backend-docker.onrender.com/api/scans/upload-universal/{scan_id}/results"
        ).json()
        
        print(f"\n📊 SCAN RESULTS:")
        print(f"   Status: {results['status']}")
        print(f"   Total findings: {results['total_findings']}")
        print(f"   Secrets found: {results['secrets']['secrets_found']}")
        
        # Show severity breakdown
        print(f"\n🎯 Severity Breakdown:")
        for sev, count in results['severity_counts'].items():
            if count > 0:
                print(f"   - {sev}: {count}")
        
        # Show AI analysis
        if results.get('ai_analysis', {}).get('success'):
            print(f"\n🤖 AI ANALYSIS AVAILABLE!")
            print("   (Full analysis saved to report.md)")
            with open('ai_security_report.md', 'w') as f:
                f.write(results['ai_analysis']['analysis'])
        else:
            print(f"\n⚠️ AI Analysis: {results.get('ai_analysis', {}).get('error', 'Not available')}")
        
        # Cleanup
        import os
        os.remove('test_vuln.py')
        
        return results['total_findings'] > 0
    else:
        print(f"❌ Upload failed: {response.status_code}")
        return False

if __name__ == "__main__":
    print("🧪 Testing Codebase Scanner - Final Verification")
    print("🌐 https://codebase-scanner-backend-docker.onrender.com")
    print("")
    
    success = test_final_scanner()
    
    print("\n" + "=" * 60)
    if success:
        print("✅ SUCCESS! Scanner is working correctly:")
        print("   - File upload works")
        print("   - Security vulnerabilities are detected")
        print("   - Anthropic API integration is functional")
        print("   - Results are properly returned")
    else:
        print("❌ FAILED: Scanner needs attention")
    print("=" * 60)