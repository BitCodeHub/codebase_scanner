#!/usr/bin/env python3
"""
Test script to verify scan results fetching
"""

import requests
import json
import sys

# Replace with your actual scan ID
SCAN_ID = sys.argv[1] if len(sys.argv) > 1 else "test-scan-id"
API_URL = "http://localhost:8000"

def test_scan_results_fetch():
    """Test fetching scan results from the backend"""
    
    print(f"Testing scan results fetch for scan ID: {SCAN_ID}")
    print("=" * 60)
    
    # Test the new endpoint
    url = f"{API_URL}/api/test/scan/{SCAN_ID}/results"
    print(f"Calling: GET {url}")
    
    try:
        response = requests.get(url)
        print(f"Status Code: {response.status_code}")
        
        data = response.json()
        print(f"\nResponse:")
        print(json.dumps(data, indent=2))
        
        if data.get("success"):
            print(f"\n✅ Successfully fetched scan data!")
            print(f"Project Name: {data.get('project_name')}")
            print(f"Result Count: {data.get('result_count')}")
            
            if data.get("scan"):
                scan = data["scan"]
                print(f"\nScan Details:")
                print(f"  - Status: {scan.get('status')}")
                print(f"  - Created: {scan.get('created_at')}")
                print(f"  - Total Issues: {scan.get('total_issues')}")
                print(f"  - Critical: {scan.get('critical_issues')}")
                print(f"  - High: {scan.get('high_issues')}")
                print(f"  - Medium: {scan.get('medium_issues')}")
                print(f"  - Low: {scan.get('low_issues')}")
            
            if data.get("results"):
                print(f"\nScan Results (Top 5):")
                for i, result in enumerate(data["results"][:5]):
                    print(f"\n  {i+1}. {result.get('title')}")
                    print(f"     Severity: {result.get('severity')}")
                    print(f"     File: {result.get('file_path')}:{result.get('line_number')}")
                    print(f"     Rule: {result.get('rule_id')}")
        else:
            print(f"\n❌ Failed to fetch scan results: {data.get('error')}")
            
    except Exception as e:
        print(f"\n❌ Error calling API: {str(e)}")

if __name__ == "__main__":
    test_scan_results_fetch()