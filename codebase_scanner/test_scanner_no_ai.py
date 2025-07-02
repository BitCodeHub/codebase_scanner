#!/usr/bin/env python3
"""
Test the universal file upload scanner WITHOUT AI analysis
"""

import requests
import os
import json
import time

# Configuration
BACKEND_URL = "https://codebase-scanner-backend-docker.onrender.com"

def test_universal_scanner_no_ai():
    print(f"🧪 Testing Universal Scanner WITHOUT AI at: {BACKEND_URL}")
    print("=" * 60)
    
    # Create a simple test Python file
    test_code = '''
# Test file with some security issues
API_KEY = "sk-1234567890abcdef"
password = "admin123"

def unsafe_query(user_input):
    query = f"SELECT * FROM users WHERE id = {user_input}"
    return query
'''
    
    # Save test file
    test_filename = "test_code.py"
    with open(test_filename, 'w') as f:
        f.write(test_code)
    
    print(f"✅ Created test file: {test_filename}")
    print(f"📏 File size: {len(test_code)} bytes")
    
    # Test the upload endpoint WITHOUT AI analysis
    print("\n🚀 Uploading file for security analysis (AI disabled)...")
    
    try:
        with open(test_filename, 'rb') as f:
            files = {'file': (test_filename, f, 'text/x-python')}
            data = {
                'enable_ai_analysis': 'false',  # Disable AI analysis
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
            print(f"📁 Filename: {result['filename']}")
            print(f"📏 File size: {result['file_size']} bytes")
            
            # Poll for results
            print("\n⏳ Waiting for scan to complete...")
            max_attempts = 20
            attempt = 0
            
            while attempt < max_attempts:
                time.sleep(2)
                
                # Check status
                status_response = requests.get(
                    f"{BACKEND_URL}/api/scans/upload-universal/{scan_id}/status",
                    timeout=10
                )
                
                if status_response.status_code == 200:
                    status_data = status_response.json()
                    status = status_data.get('status', 'unknown')
                    
                    if status == 'completed':
                        print("\n✅ Scan completed successfully!")
                        
                        # Get full results
                        results_response = requests.get(
                            f"{BACKEND_URL}/api/scans/upload-universal/{scan_id}/results",
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
    print("📊 SECURITY SCAN RESULTS (WITHOUT AI ANALYSIS)")
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
    
    # AI Analysis status
    ai_analysis = results.get('ai_analysis', {})
    print(f"\n🤖 AI Analysis: {'Disabled' if not ai_analysis else 'Not available'}")

if __name__ == "__main__":
    test_universal_scanner_no_ai()