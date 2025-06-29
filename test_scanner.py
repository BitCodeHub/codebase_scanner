#!/usr/bin/env python3
"""Test script to verify enhanced dependency scanning"""
import requests
import json
import time
import sys

API_BASE = "http://localhost:8000/api"

def test_dependency_scanner():
    print("🧪 Testing Enhanced Security Scanner with Dependencies")
    print("=" * 60)
    
    # 1. Login
    print("1. Logging in...")
    login_data = {
        "username": "demo",
        "password": "demo123"
    }
    
    response = requests.post(f"{API_BASE}/auth/token", data=login_data)
    if response.status_code != 200:
        print(f"❌ Login failed: {response.text}")
        return False
    
    token = response.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    print("✅ Login successful")
    
    # 2. Get first project
    print("\n2. Getting project...")
    response = requests.get(f"{API_BASE}/projects", headers=headers)
    if response.status_code != 200:
        print(f"❌ Failed to get projects: {response.text}")
        return False
    
    projects = response.json()
    if not projects:
        print("❌ No projects found")
        return False
    
    project_id = projects[0]["id"]
    print(f"✅ Using project: {projects[0]['name']} (ID: {project_id})")
    
    # 3. Start a scan
    print("\n3. Starting security scan...")
    scan_data = {
        "project_id": project_id,
        "scan_type": "security"
    }
    
    response = requests.post(f"{API_BASE}/scans", json=scan_data, headers=headers)
    if response.status_code != 200:
        print(f"❌ Failed to start scan: {response.text}")
        return False
    
    scan = response.json()
    scan_id = scan["id"]
    print(f"✅ Scan started (ID: {scan_id})")
    
    # 4. Wait for scan completion
    print("\n4. Waiting for scan completion...")
    max_wait = 60  # seconds
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
        
        time.sleep(5)
        waited += 5
    
    if waited >= max_wait:
        print("❌ Scan timed out")
        return False
    
    print("✅ Scan completed")
    
    # 5. Get scan results
    print("\n5. Analyzing scan results...")
    response = requests.get(f"{API_BASE}/scans/{scan_id}/results", headers=headers)
    if response.status_code != 200:
        print(f"❌ Failed to get results: {response.text}")
        return False
    
    results = response.json()
    print(f"✅ Found {len(results)} security issues")
    
    # 6. Analyze dependency features
    print("\n6. Checking dependency analysis features...")
    
    dependency_vulns = [r for r in results if r.get("rule_id") == "SECURITY-DEP-001"]
    code_vulns_with_deps = [r for r in results if r.get("affected_packages")]
    
    print(f"   📦 Dependency vulnerabilities: {len(dependency_vulns)}")
    print(f"   🔗 Code vulnerabilities with dependency info: {len(code_vulns_with_deps)}")
    
    # Show detailed results
    for vuln in dependency_vulns:
        print(f"   • {vuln['title']} - {vuln['severity']}")
        if vuln.get('affected_packages'):
            print(f"     Packages: {', '.join(vuln['affected_packages'])}")
    
    for vuln in code_vulns_with_deps:
        print(f"   • {vuln['title']} (affects: {', '.join(vuln['affected_packages'])})")
    
    # 7. Check for expected enhancements
    print("\n7. Verifying enhanced features...")
    
    enhanced_features = {
        "CVSS Scores": any(r.get("cvss_score") for r in results),
        "OWASP Categories": any(r.get("owasp_category") for r in results),
        "Remediation Examples": any(r.get("remediation_example") for r in results),
        "Compliance Mappings": any(r.get("compliance_mappings") for r in results),
        "Dependency Information": any(r.get("affected_packages") for r in results),
        "Fix Priority": any(r.get("fix_priority") for r in results)
    }
    
    for feature, present in enhanced_features.items():
        status = "✅" if present else "❌"
        print(f"   {status} {feature}")
    
    all_enhanced = all(enhanced_features.values())
    
    print("\n" + "=" * 60)
    if all_enhanced:
        print("🎉 All enhanced features are working correctly!")
        print("🚀 The scanner is ready for professional security analysis!")
    else:
        print("⚠️  Some enhanced features may need attention")
    
    return all_enhanced

if __name__ == "__main__":
    success = test_dependency_scanner()
    sys.exit(0 if success else 1)