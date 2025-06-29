#!/usr/bin/env python3
"""Test dependency scanning on the uploaded project"""
import requests
import json
import time

API_BASE = "http://localhost:8000/api"
PROJECT_ID = 5  # The project we just uploaded

def test_dependency_project():
    print("🧪 Testing Dependency Scanning on Uploaded Project")
    print("=" * 60)
    
    # 1. Login
    login_data = {"username": "demo", "password": "demo123"}
    response = requests.post(f"{API_BASE}/auth/token", data=login_data)
    token = response.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    
    # 2. Start scan on the dependency test project
    print(f"1. Starting scan on project {PROJECT_ID}...")
    scan_data = {
        "project_id": PROJECT_ID,
        "scan_type": "security"
    }
    
    response = requests.post(f"{API_BASE}/scans", json=scan_data, headers=headers)
    if response.status_code != 200:
        print(f"❌ Failed to start scan: {response.text}")
        return False
    
    scan = response.json()
    scan_id = scan["id"]
    print(f"✅ Scan started (ID: {scan_id})")
    
    # 3. Wait for completion
    print("\n2. Waiting for scan completion...")
    max_wait = 60
    waited = 0
    
    while waited < max_wait:
        response = requests.get(f"{API_BASE}/scans/{scan_id}", headers=headers)
        if response.status_code == 200:
            scan_status = response.json()["status"]
            print(f"   Status: {scan_status}")
            
            if scan_status == "completed":
                break
            elif scan_status == "failed":
                print("❌ Scan failed")
                return False
        
        time.sleep(3)
        waited += 3
    
    # 4. Get results and analyze
    print("\n3. Analyzing dependency scanning results...")
    response = requests.get(f"{API_BASE}/scans/{scan_id}/results", headers=headers)
    results = response.json()
    
    print(f"✅ Total vulnerabilities found: {len(results)}")
    
    # Analyze results
    dependency_vulns = []
    code_vulns_with_deps = []
    
    for result in results:
        print(f"\n📋 {result['rule_id']}: {result['title']}")
        print(f"   Severity: {result['severity']}")
        print(f"   Category: {result.get('category', 'N/A')}")
        
        if result.get('rule_id') == 'SECURITY-DEP-001':
            dependency_vulns.append(result)
            print("   🔍 This is a DEPENDENCY vulnerability")
            
        if result.get('affected_packages'):
            code_vulns_with_deps.append(result)
            print(f"   📦 Affected packages: {result['affected_packages']}")
            
            if result.get('vulnerable_versions'):
                print(f"   ⚠️  Vulnerable versions: {result['vulnerable_versions']}")
            
            if result.get('fixed_versions'):
                print(f"   ✅ Fixed versions: {result['fixed_versions']}")
    
    # Summary
    print("\n" + "=" * 60)
    print("📊 DEPENDENCY ANALYSIS SUMMARY:")
    print(f"   📦 Direct dependency vulnerabilities: {len(dependency_vulns)}")
    print(f"   🔗 Code vulnerabilities with dependency info: {len(code_vulns_with_deps)}")
    
    # Expected results
    expected_packages = ['lodash', 'express', 'jquery']
    found_packages = set()
    
    for vuln in dependency_vulns:
        if vuln.get('affected_packages'):
            found_packages.update(vuln['affected_packages'])
    
    for vuln in code_vulns_with_deps:
        if vuln.get('affected_packages'):
            found_packages.update(vuln['affected_packages'])
    
    print(f"   🎯 Expected vulnerable packages: {expected_packages}")
    print(f"   ✅ Found packages: {list(found_packages)}")
    
    success = len(dependency_vulns) > 0 or len(code_vulns_with_deps) > 0
    
    if success:
        print("\n🎉 DEPENDENCY SCANNING IS WORKING!")
        print("✅ The enhanced scanner successfully detected dependency information")
    else:
        print("\n⚠️  DEPENDENCY SCANNING NEEDS INVESTIGATION")
        print("❌ No dependency information was detected")
    
    return success

if __name__ == "__main__":
    test_dependency_project()