#!/usr/bin/env python3
"""
Scan a GitHub repository using the Codebase Scanner backend API
"""

import requests
import json
import time
from datetime import datetime

# Configuration
BACKEND_URL = "https://codebase-scanner-backend-docker.onrender.com"
GITHUB_REPO = "https://github.com/Hyundai-Kia-Connect/hyundai_kia_connect_api"

def scan_repository():
    """Scan a GitHub repository for security vulnerabilities"""
    print(f"\n🔍 Scanning GitHub Repository: {GITHUB_REPO}")
    print("=" * 70)
    
    # Prepare the scan request
    scan_data = {
        "repository_url": GITHUB_REPO,
        "scan_type": "full",
        "enable_ai_analysis": False  # Disabled as requested
    }
    
    try:
        # Initiate the scan
        print("\n📡 Initiating scan...")
        response = requests.post(
            f"{BACKEND_URL}/api/scans/github",
            json=scan_data,
            headers={"Content-Type": "application/json"},
            timeout=30
        )
        
        if response.status_code == 200:
            result = response.json()
            scan_id = result.get("scan_id")
            print(f"✅ Scan initiated successfully!")
            print(f"📋 Scan ID: {scan_id}")
            
            # Poll for scan results
            print("\n⏳ Waiting for scan to complete...")
            max_attempts = 60  # 5 minutes max
            attempt = 0
            
            while attempt < max_attempts:
                time.sleep(5)  # Check every 5 seconds
                
                # Get scan status
                status_response = requests.get(
                    f"{BACKEND_URL}/api/scans/{scan_id}/status",
                    timeout=10
                )
                
                if status_response.status_code == 200:
                    status_data = status_response.json()
                    status = status_data.get("status", "unknown")
                    progress = status_data.get("progress", 0)
                    
                    print(f"\r📊 Status: {status} | Progress: {progress}%", end="", flush=True)
                    
                    if status == "completed":
                        print("\n\n✅ Scan completed successfully!")
                        
                        # Get full scan results
                        results_response = requests.get(
                            f"{BACKEND_URL}/api/scans/{scan_id}/results",
                            timeout=30
                        )
                        
                        if results_response.status_code == 200:
                            scan_results = results_response.json()
                            display_results(scan_results)
                        else:
                            print(f"❌ Failed to retrieve results: {results_response.status_code}")
                        break
                    
                    elif status == "failed":
                        print(f"\n\n❌ Scan failed: {status_data.get('error', 'Unknown error')}")
                        break
                
                attempt += 1
            
            if attempt >= max_attempts:
                print("\n\n⚠️ Scan timed out after 5 minutes")
        
        else:
            print(f"❌ Failed to initiate scan: {response.status_code}")
            if response.headers.get('content-type', '').startswith('application/json'):
                error_data = response.json()
                print(f"Error: {error_data.get('detail', 'Unknown error')}")
            else:
                print(f"Response: {response.text[:200]}")
    
    except requests.exceptions.RequestException as e:
        print(f"❌ Request failed: {e}")

def display_results(results):
    """Display scan results in a formatted manner"""
    print("\n" + "=" * 70)
    print("📊 SCAN RESULTS SUMMARY")
    print("=" * 70)
    
    # Repository info
    repo_info = results.get("repository_info", {})
    print(f"\n📁 Repository: {repo_info.get('name', 'Unknown')}")
    print(f"🌟 Stars: {repo_info.get('stars', 0)}")
    print(f"🍴 Forks: {repo_info.get('forks', 0)}")
    print(f"📅 Last Updated: {repo_info.get('last_updated', 'Unknown')}")
    
    # Overall statistics
    summary = results.get("summary", {})
    total_findings = summary.get("total_findings", 0)
    print(f"\n🔍 Total Security Findings: {total_findings}")
    
    # Severity breakdown
    severity_counts = summary.get("severity_counts", {})
    print("\n📈 Findings by Severity:")
    print(f"  🔴 Critical: {severity_counts.get('critical', 0)}")
    print(f"  🟠 High: {severity_counts.get('high', 0)}")
    print(f"  🟡 Medium: {severity_counts.get('medium', 0)}")
    print(f"  🟢 Low: {severity_counts.get('low', 0)}")
    print(f"  ℹ️  Info: {severity_counts.get('info', 0)}")
    
    # Tool results
    tool_results = results.get("tool_results", {})
    print("\n🛠️ Results by Security Tool:")
    for tool_name, tool_data in tool_results.items():
        findings_count = len(tool_data.get("findings", []))
        if tool_data.get("success"):
            print(f"  ✅ {tool_name}: {findings_count} findings")
        else:
            print(f"  ❌ {tool_name}: Failed - {tool_data.get('error', 'Unknown error')}")
    
    # Top findings
    all_findings = results.get("findings", [])
    if all_findings:
        print(f"\n🚨 Top Security Issues (showing first 10):")
        for i, finding in enumerate(all_findings[:10], 1):
            print(f"\n  {i}. {finding.get('title', 'Untitled Finding')}")
            print(f"     Severity: {finding.get('severity', 'Unknown')}")
            print(f"     Tool: {finding.get('tool', 'Unknown')}")
            print(f"     File: {finding.get('file_path', 'Unknown')}")
            if finding.get('line_number'):
                print(f"     Line: {finding.get('line_number')}")
            print(f"     Description: {finding.get('description', 'No description')[:100]}...")
    
    # Language statistics
    languages = results.get("languages", {})
    if languages:
        print("\n💻 Language Distribution:")
        for lang, percentage in languages.items():
            print(f"  {lang}: {percentage}%")
    
    # Scan metadata
    metadata = results.get("metadata", {})
    print(f"\n⏱️ Scan Duration: {metadata.get('duration', 'Unknown')} seconds")
    print(f"📅 Scan Date: {metadata.get('scan_date', datetime.now().isoformat())}")
    
    # Save full results to file
    output_file = f"scan_results_{GITHUB_REPO.split('/')[-1]}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)
    print(f"\n💾 Full results saved to: {output_file}")

def test_scanner_tools():
    """Test which scanner tools are available"""
    print("\n🔧 Testing Scanner Tools Availability...")
    try:
        response = requests.get(f"{BACKEND_URL}/api/test/scanner-tools", timeout=10)
        if response.status_code == 200:
            data = response.json()
            tools = data.get("tools", {})
            available = data.get("available_tools", 0)
            total = data.get("total_tools", 0)
            
            print(f"\n✅ {available}/{total} tools available:")
            for tool_name, tool_info in tools.items():
                if tool_info.get("available"):
                    print(f"  ✅ {tool_name} v{tool_info.get('version', 'Unknown')}")
                else:
                    print(f"  ❌ {tool_name}: {tool_info.get('error', 'Not available')}")
    except Exception as e:
        print(f"❌ Failed to test tools: {e}")

if __name__ == "__main__":
    print("🚀 Codebase Scanner - GitHub Repository Analysis")
    print("=" * 70)
    
    # First test available tools
    test_scanner_tools()
    
    # Then scan the repository
    scan_repository()