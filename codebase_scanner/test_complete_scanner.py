#!/usr/bin/env python3
"""
Complete test of universal scanner with file processing and AI analysis
"""

import requests
import os
import json
import time
from datetime import datetime

BACKEND_URL = "https://codebase-scanner-backend-docker.onrender.com"

def test_complete_scanner():
    print("🧪 Complete Universal Scanner Test")
    print("=" * 60)
    
    # Create a comprehensive test file with various security issues
    test_code = '''#!/usr/bin/env python3
"""
Sample vulnerable application for testing
"""
import os
import pickle
import requests
import mysql.connector
import subprocess
import hashlib
import random
from flask import Flask, request

# SECURITY ISSUE: Hardcoded API keys and secrets
API_KEY = "sk-proj-1234567890abcdef-ghijklmnop"
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
DATABASE_PASSWORD = "admin123"
JWT_SECRET = "super-secret-jwt-key"
GITHUB_TOKEN = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"

app = Flask(__name__)

# SECURITY ISSUE: SQL Injection vulnerability
@app.route('/user/<user_id>')
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

# SECURITY ISSUE: Command injection
@app.route('/ping')
def ping():
    host = request.args.get('host')
    # Vulnerable to command injection
    cmd = f"ping -c 1 {host}"
    output = subprocess.check_output(cmd, shell=True)
    return output

# SECURITY ISSUE: Unsafe deserialization
@app.route('/load')
def load_data():
    filename = request.args.get('file')
    with open(filename, 'rb') as f:
        # Vulnerable to deserialization attacks
        data = pickle.load(f)
    return str(data)

# SECURITY ISSUE: Weak password hashing
def hash_password(password):
    # MD5 is cryptographically broken
    return hashlib.md5(password.encode()).hexdigest()

# SECURITY ISSUE: Insecure random number generation
def generate_session_token():
    # Not cryptographically secure
    return ''.join([str(random.randint(0, 9)) for _ in range(32)])

# SECURITY ISSUE: Path traversal vulnerability
@app.route('/read')
def read_file():
    filename = request.args.get('file')
    # Vulnerable to path traversal
    with open(f"/var/data/{filename}", 'r') as f:
        return f.read()

# SECURITY ISSUE: Hardcoded admin credentials
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "password123"

# SECURITY ISSUE: Eval usage
@app.route('/calc')
def calculate():
    expression = request.args.get('expr')
    # Dangerous eval usage
    result = eval(expression)
    return str(result)

# SECURITY ISSUE: SSL verification disabled
def make_api_request(url):
    # SSL verification disabled
    return requests.get(url, verify=False)

# SECURITY ISSUE: Debug mode enabled in production
if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0')
'''
    
    test_filename = "vulnerable_webapp.py"
    
    print(f"📝 Creating test file: {test_filename}")
    with open(test_filename, 'w') as f:
        f.write(test_code)
    
    print(f"📏 File size: {len(test_code)} bytes")
    print(f"📊 Security issues included: 11+ vulnerabilities")
    
    # Test 1: Upload with AI analysis enabled
    print("\n🚀 Test 1: Uploading file WITH AI analysis...")
    
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
            print(f"🤖 AI Analysis: Enabled")
            
            # Wait for scan to complete
            print("\n⏳ Waiting for scan to complete (this may take 30-60 seconds)...")
            
            # Initial wait
            time.sleep(10)
            
            max_attempts = 30
            attempt = 0
            scan_completed = False
            
            while attempt < max_attempts and not scan_completed:
                time.sleep(3)
                
                # Check results
                results_response = requests.get(
                    f"{BACKEND_URL}/api/scans/upload-universal/{scan_id}/results",
                    timeout=30
                )
                
                if results_response.status_code == 200:
                    scan_results = results_response.json()
                    status = scan_results.get('status', 'unknown')
                    
                    if status == 'completed':
                        scan_completed = True
                        print("\n✅ Scan completed successfully!")
                        display_results(scan_results, with_ai=True)
                    elif status == 'failed':
                        print(f"\n❌ Scan failed: {scan_results.get('error', 'Unknown error')}")
                        break
                    else:
                        print(f"\r⏳ Status: {status} (attempt {attempt+1}/{max_attempts})...", end="", flush=True)
                
                attempt += 1
            
            if not scan_completed:
                print("\n⚠️ Scan timed out - fetching partial results...")
                if 'scan_results' in locals():
                    display_results(scan_results, with_ai=True)
        
        else:
            print(f"❌ Upload failed: {response.status_code}")
            print(f"Response: {response.text}")
            
    except Exception as e:
        print(f"❌ Error in Test 1: {e}")
    
    # Test 2: Quick test without AI
    print("\n\n🚀 Test 2: Quick scan WITHOUT AI analysis...")
    
    try:
        with open(test_filename, 'rb') as f:
            files = {'file': (test_filename, f, 'text/x-python')}
            data = {
                'enable_ai_analysis': 'false',
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
            print(f"🤖 AI Analysis: Disabled")
            
            # Wait less time for non-AI scan
            print("\n⏳ Waiting for scan to complete...")
            time.sleep(8)
            
            # Get results
            results_response = requests.get(
                f"{BACKEND_URL}/api/scans/upload-universal/{scan_id}/results",
                timeout=30
            )
            
            if results_response.status_code == 200:
                scan_results = results_response.json()
                if scan_results.get('status') == 'completed':
                    print("\n✅ Scan completed!")
                    display_results(scan_results, with_ai=False)
    
    except Exception as e:
        print(f"❌ Error in Test 2: {e}")
    
    finally:
        # Cleanup
        if os.path.exists(test_filename):
            os.remove(test_filename)
            print(f"\n🧹 Cleaned up test file: {test_filename}")

def display_results(results, with_ai=True):
    """Display scan results in a formatted manner"""
    print("\n" + "=" * 60)
    print(f"📊 SECURITY SCAN RESULTS {'(WITH AI)' if with_ai else '(WITHOUT AI)'}")
    print("=" * 60)
    
    # Basic info
    print(f"\n📁 File: {results.get('filename', 'Unknown')}")
    print(f"📈 Total Findings: {results.get('total_findings', 0)}")
    print(f"🔍 Files Scanned: {results.get('files_scanned', 0)}")
    
    # Languages detected
    languages = results.get('languages', {})
    if languages:
        print(f"💻 Languages: {', '.join(languages.keys())} (files: {list(languages.values())})")
    
    # Severity breakdown
    severity_counts = results.get('severity_counts', {})
    if any(severity_counts.values()):
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
    
    # Secrets found
    secrets = results.get('secrets', {})
    if secrets.get('secrets_found', 0) > 0:
        print(f"\n🔐 Secrets Found: {secrets['secrets_found']}")
        for secret in secrets.get('findings', [])[:5]:
            print(f"  - {secret.get('title', 'Unknown')}")
            if secret.get('secret_type'):
                print(f"    Type: {secret['secret_type']}")
    
    # Top security findings
    findings = results.get('findings', [])
    if findings:
        print(f"\n🚨 Top Security Issues (showing first 10 of {len(findings)}):")
        for i, finding in enumerate(findings[:10], 1):
            severity = finding.get('severity', 'unknown').upper()
            print(f"\n  {i}. [{severity}] {finding.get('title', 'Unknown issue')}")
            print(f"     Tool: {finding.get('tool', 'Unknown')}")
            if finding.get('file'):
                print(f"     Location: {finding.get('file')}:{finding.get('line', '?')}")
            if finding.get('code'):
                code_preview = finding['code'][:60].strip()
                if len(finding['code']) > 60:
                    code_preview += "..."
                print(f"     Code: {code_preview}")
    
    # AI Analysis Results
    if with_ai:
        ai_analysis = results.get('ai_analysis', {})
        if ai_analysis:
            if ai_analysis.get('success'):
                print("\n" + "=" * 60)
                print("🤖 CLAUDE AI SECURITY ANALYSIS")
                print("=" * 60)
                analysis_text = ai_analysis.get('analysis', 'No analysis available')
                print(f"\n{analysis_text}")
                
                # Save full report
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                report_file = f"security_report_{timestamp}.md"
                with open(report_file, 'w') as f:
                    f.write(f"# Security Analysis Report\n\n")
                    f.write(f"**File:** {results.get('filename', 'Unknown')}\n")
                    f.write(f"**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write(f"**Total Findings:** {results.get('total_findings', 0)}\n\n")
                    f.write("## AI Analysis\n\n")
                    f.write(analysis_text)
                print(f"\n💾 Full report saved to: {report_file}")
            else:
                error = ai_analysis.get('error', 'Unknown error')
                print(f"\n⚠️ AI Analysis Failed: {error}")
                if "credit balance" in error:
                    print("   → The Anthropic API key needs more credits")
    
    # Save raw results
    results_file = f"scan_results_{results.get('scan_id', 'unknown')}.json"
    with open(results_file, 'w') as f:
        json.dump(results, f, indent=2)
    print(f"\n📋 Raw results saved to: {results_file}")

if __name__ == "__main__":
    print("🔧 Testing Codebase Scanner - Universal File Upload")
    print("🌐 Backend: " + BACKEND_URL)
    print("📅 Test Date: " + datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
    print("\n")
    
    test_complete_scanner()