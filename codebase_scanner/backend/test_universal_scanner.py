#!/usr/bin/env python3
"""
Test the universal file upload scanner with Claude AI analysis
"""

import requests
import os
import json
import time
from datetime import datetime

# Configuration
BACKEND_URL = "https://codebase-scanner-backend-docker.onrender.com"
LOCAL_URL = "http://localhost:8000"

def test_universal_scanner(use_local=False):
    base_url = LOCAL_URL if use_local else BACKEND_URL
    print(f"🧪 Testing Universal Scanner at: {base_url}")
    print("=" * 60)
    
    # Create a test Python file with security issues
    test_code = '''
import os
import pickle
import requests
import mysql.connector

# Security Issue 1: Hardcoded credentials
API_KEY = "sk-1234567890abcdef"
DATABASE_PASSWORD = "admin123"
AWS_SECRET_KEY = "AKIAIOSFODNN7EXAMPLE"

# Security Issue 2: SQL Injection vulnerability
def get_user(user_id):
    conn = mysql.connector.connect(
        host="localhost",
        user="root",
        password=DATABASE_PASSWORD,
        database="users"
    )
    cursor = conn.cursor()
    # Vulnerable to SQL injection
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
    return cursor.fetchone()

# Security Issue 3: Unsafe pickle usage
def load_data(filename):
    with open(filename, 'rb') as f:
        # Unsafe deserialization
        return pickle.load(f)

# Security Issue 4: No input validation
def process_input(user_input):
    # Direct execution of user input
    exec(user_input)

# Security Issue 5: Insecure random
import random
def generate_token():
    return ''.join([str(random.randint(0, 9)) for _ in range(16)])

# Security Issue 6: Disabled SSL verification
def make_request(url):
    return requests.get(url, verify=False)

# Security Issue 7: Weak hashing
import hashlib
def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()

if __name__ == "__main__":
    print("This code has multiple security vulnerabilities!")
'''
    
    # Save test file
    test_filename = "vulnerable_code.py"
    with open(test_filename, 'w') as f:
        f.write(test_code)
    
    print(f"✅ Created test file: {test_filename}")
    print(f"📏 File size: {len(test_code)} bytes")
    
    # Test the upload endpoint
    print("\n🚀 Uploading file for security analysis...")
    
    try:
        with open(test_filename, 'rb') as f:
            files = {'file': (test_filename, f, 'text/x-python')}
            data = {
                'enable_ai_analysis': 'true',
                'scan_type': 'comprehensive'
            }
            
            response = requests.post(
                f"{base_url}/api/scans/upload-universal",
                files=files,
                data=data,
                timeout=30
            )
        
        if response.status_code == 200:
            result = response.json()
            scan_id = result['scan_id']
            print(f"✅ Upload successful!")
            print(f"📋 Scan ID: {scan_id}")
            print(f"📁 Filename: {result['filename']}")
            print(f"📏 File size: {result['file_size']} bytes")
            
            # Poll for results
            print("\n⏳ Waiting for scan to complete...")
            max_attempts = 30
            attempt = 0
            
            while attempt < max_attempts:
                time.sleep(3)
                
                # Check status
                status_response = requests.get(
                    f"{base_url}/api/scans/upload-universal/{scan_id}/status",
                    timeout=10
                )
                
                if status_response.status_code == 200:
                    status_data = status_response.json()
                    status = status_data.get('status', 'unknown')
                    
                    if status == 'completed':
                        print("\n✅ Scan completed successfully!")
                        
                        # Get full results
                        results_response = requests.get(
                            f"{base_url}/api/scans/upload-universal/{scan_id}/results",
                            timeout=30
                        )
                        
                        if results_response.status_code == 200:
                            scan_results = results_response.json()
                            display_results(scan_results)
                        break
                    
                    elif status == 'failed':
                        print(f"\n❌ Scan failed")
                        break
                    
                    else:
                        print(f"\r⏳ Status: {status}...", end="", flush=True)
                
                attempt += 1
            
            if attempt >= max_attempts:
                print("\n⚠️ Scan timed out")
        
        else:
            print(f"❌ Upload failed: {response.status_code}")
            print(f"Response: {response.text}")
            
    except Exception as e:
        print(f"❌ Error: {e}")
    
    finally:
        # Clean up
        if os.path.exists(test_filename):
            os.remove(test_filename)
            print(f"\n🧹 Cleaned up test file: {test_filename}")

def display_results(results):
    """Display scan results in a formatted manner"""
    print("\n" + "=" * 60)
    print("📊 SECURITY SCAN RESULTS")
    print("=" * 60)
    
    # Summary
    print(f"\n📁 File: {results.get('filename', 'Unknown')}")
    print(f"🔍 Languages: {', '.join(results.get('languages', {}).keys())}")
    print(f"📈 Total Findings: {results.get('total_findings', 0)}")
    
    # Severity breakdown
    severity_counts = results.get('severity_counts', {})
    print("\n🎯 Severity Breakdown:")
    print(f"  🔴 Critical: {severity_counts.get('critical', 0)}")
    print(f"  🟠 High: {severity_counts.get('high', 0)}")
    print(f"  🟡 Medium: {severity_counts.get('medium', 0)}")
    print(f"  🔵 Low: {severity_counts.get('low', 0)}")
    print(f"  ⚪ Info: {severity_counts.get('info', 0)}")
    
    # Secrets
    secrets = results.get('secrets', {})
    if secrets.get('secrets_found', 0) > 0:
        print(f"\n🔐 Secrets Found: {secrets['secrets_found']}")
        for secret in secrets.get('findings', [])[:3]:
            print(f"  - {secret.get('title', 'Unknown')}")
    
    # Top findings
    findings = results.get('findings', [])
    if findings:
        print(f"\n🚨 Top Security Issues (showing first 5):")
        for i, finding in enumerate(findings[:5], 1):
            print(f"\n  {i}. [{finding.get('severity', 'unknown').upper()}] {finding.get('title', 'Unknown')}")
            print(f"     Tool: {finding.get('tool', 'Unknown')}")
            print(f"     File: {finding.get('file', 'Unknown')}:{finding.get('line', '?')}")
    
    # AI Analysis
    ai_analysis = results.get('ai_analysis', {})
    if ai_analysis.get('success'):
        print("\n" + "=" * 60)
        print("🤖 CLAUDE AI SECURITY ANALYSIS")
        print("=" * 60)
        print("\n" + ai_analysis.get('analysis', 'No analysis available'))
        
        # Save AI analysis to file
        analysis_file = f"ai_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
        with open(analysis_file, 'w') as f:
            f.write(f"# Security Analysis Report\n\n")
            f.write(f"File: {results.get('filename', 'Unknown')}\n")
            f.write(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            f.write(ai_analysis.get('analysis', ''))
        print(f"\n💾 AI analysis saved to: {analysis_file}")
    else:
        print("\n⚠️ AI analysis not available")
        if ai_analysis.get('error'):
            print(f"   Error: {ai_analysis['error']}")

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description='Test Universal File Scanner')
    parser.add_argument('--local', action='store_true', help='Use local backend')
    args = parser.parse_args()
    
    test_universal_scanner(use_local=args.local)