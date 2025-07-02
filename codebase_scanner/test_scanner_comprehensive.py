#!/usr/bin/env python3
"""
Test the universal scanner with comprehensive security issues
"""

import requests
import os
import json
import time

BACKEND_URL = "https://codebase-scanner-backend-docker.onrender.com"

def test_with_security_issues():
    print(f"🧪 Testing Universal Scanner at: {BACKEND_URL}")
    print("=" * 60)
    
    # Create a Python file with various security issues
    test_code = '''#!/usr/bin/env python3
import os
import pickle
import requests
import mysql.connector
import subprocess
import hashlib
import random

# Hardcoded secrets
API_KEY = "sk-proj-1234567890abcdef"
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
DATABASE_PASSWORD = "admin123"
JWT_SECRET = "my-super-secret-key"

# SQL Injection vulnerability
def get_user(user_id):
    conn = mysql.connector.connect(host="localhost", user="root", password=DATABASE_PASSWORD)
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE id = {user_id}"  # Vulnerable to SQL injection
    cursor.execute(query)
    return cursor.fetchone()

# Command injection
def run_command(user_input):
    cmd = f"echo {user_input}"
    subprocess.call(cmd, shell=True)  # Vulnerable to command injection

# Unsafe deserialization
def load_user_data(filename):
    with open(filename, 'rb') as f:
        return pickle.load(f)  # Vulnerable to deserialization attacks

# Weak hashing
def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()  # Weak hash algorithm

# Insecure random
def generate_token():
    return ''.join([str(random.randint(0, 9)) for _ in range(16)])  # Not cryptographically secure

# Path traversal
def read_file(filename):
    with open(f"/var/data/{filename}", 'r') as f:  # Vulnerable to path traversal
        return f.read()

# Hardcoded admin credentials
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "password123"

# Eval usage
def calculate(expression):
    return eval(expression)  # Dangerous eval usage

# SSL verification disabled
def make_request(url):
    return requests.get(url, verify=False)  # SSL verification disabled

if __name__ == "__main__":
    print("This file contains multiple security vulnerabilities!")
'''
    
    test_filename = "vulnerable_app.py"
    with open(test_filename, 'w') as f:
        f.write(test_code)
    
    print(f"✅ Created test file: {test_filename}")
    print(f"📏 File size: {len(test_code)} bytes")
    
    # Test with AI analysis enabled
    print("\n🚀 Uploading file for security analysis (WITH AI)...")
    
    try:
        with open(test_filename, 'rb') as f:
            files = {'file': (test_filename, f, 'text/x-python')}
            data = {
                'enable_ai_analysis': 'true',
                'scan_type': 'comprehensive'
            }
            
            response = requests.post(
                f"{BACKEND_URL}/api/scans/upload-universal",
                files=files,
                data=data,
                timeout=30
            )
        
        if response.status_code == 200:
            result = response.json()
            scan_id = result['scan_id']
            print(f"✅ Upload successful!")
            print(f"📋 Scan ID: {scan_id}")
            
            # Wait a bit longer for processing
            print("\n⏳ Waiting for scan to complete...")
            time.sleep(5)  # Initial wait
            
            max_attempts = 30
            attempt = 0
            
            while attempt < max_attempts:
                time.sleep(3)
                
                # Check results directly
                results_response = requests.get(
                    f"{BACKEND_URL}/api/scans/upload-universal/{scan_id}/results",
                    timeout=30
                )
                
                if results_response.status_code == 200:
                    scan_results = results_response.json()
                    if scan_results.get('status') == 'completed':
                        print("\n✅ Scan completed!")
                        display_results(scan_results)
                        break
                    else:
                        print(f"\r⏳ Status: {scan_results.get('status', 'processing')}...", end="", flush=True)
                
                attempt += 1
            
            if attempt >= max_attempts:
                print("\n⚠️ Scan timed out - fetching whatever results are available")
                if 'scan_results' in locals():
                    display_results(scan_results)
        
        else:
            print(f"❌ Upload failed: {response.status_code}")
            print(f"Response: {response.text}")
            
    except Exception as e:
        print(f"❌ Error: {e}")
    
    finally:
        if os.path.exists(test_filename):
            os.remove(test_filename)
            print(f"\n🧹 Cleaned up test file: {test_filename}")

def display_results(results):
    """Display scan results"""
    print("\n" + "=" * 60)
    print("📊 SECURITY SCAN RESULTS")
    print("=" * 60)
    
    print(f"\n📁 File: {results.get('filename', 'Unknown')}")
    print(f"📈 Total Findings: {results.get('total_findings', 0)}")
    print(f"🔍 Files Scanned: {results.get('files_scanned', 0)}")
    
    # Severity breakdown
    severity_counts = results.get('severity_counts', {})
    print("\n🎯 Severity Breakdown:")
    for severity, count in severity_counts.items():
        if count > 0:
            emoji = {
                'critical': '🔴',
                'high': '🟠',
                'medium': '🟡',
                'low': '🔵',
                'info': '⚪'
            }.get(severity, '⚫')
            print(f"  {emoji} {severity.title()}: {count}")
    
    # Secrets
    secrets = results.get('secrets', {})
    if secrets.get('secrets_found', 0) > 0:
        print(f"\n🔐 Secrets Found: {secrets['secrets_found']}")
        for secret in secrets.get('findings', [])[:5]:
            print(f"  - {secret.get('title', 'Unknown')}")
    
    # Top findings
    findings = results.get('findings', [])
    if findings:
        print(f"\n🚨 Top Security Issues (showing first 10):")
        for i, finding in enumerate(findings[:10], 1):
            print(f"\n  {i}. [{finding.get('severity', 'unknown').upper()}] {finding.get('title', 'Unknown')}")
            print(f"     Tool: {finding.get('tool', 'Unknown')}")
            if finding.get('file'):
                print(f"     Location: {finding.get('file')}:{finding.get('line', '?')}")
    
    # AI Analysis
    ai_analysis = results.get('ai_analysis', {})
    if ai_analysis:
        if ai_analysis.get('success'):
            print("\n" + "=" * 60)
            print("🤖 AI SECURITY ANALYSIS")
            print("=" * 60)
            print(ai_analysis.get('analysis', 'No analysis available'))
        elif ai_analysis.get('error'):
            print(f"\n⚠️ AI Analysis Error: {ai_analysis['error']}")
    
    # Raw results for debugging
    print(f"\n\n📋 Raw scan results saved to: scan_results_{results.get('scan_id', 'unknown')}.json")
    with open(f"scan_results_{results.get('scan_id', 'unknown')}.json", 'w') as f:
        json.dump(results, f, indent=2)

if __name__ == "__main__":
    test_with_security_issues()