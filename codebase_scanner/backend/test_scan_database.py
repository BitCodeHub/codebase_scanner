#!/usr/bin/env python3
"""Test scan database storage and retrieval"""

import os
import sys
from dotenv import load_dotenv
from supabase import create_client

# Load environment variables
load_dotenv()

def test_scan_data(scan_id=None):
    print("🔍 Testing scan data in database...\n")
    
    supabase_url = os.getenv("SUPABASE_URL")
    supabase_key = os.getenv("SUPABASE_SERVICE_ROLE_KEY")
    
    if not supabase_url or not supabase_key:
        print("❌ Missing Supabase credentials")
        return
    
    supabase = create_client(supabase_url, supabase_key)
    
    if scan_id:
        print(f"Looking for scan ID: {scan_id}\n")
        
        # Check scans table
        print("1️⃣ Checking scans table...")
        try:
            scan_result = supabase.table("scans").select("*").eq("id", scan_id).execute()
            if scan_result.data:
                scan = scan_result.data[0]
                print("✅ Scan found!")
                print(f"   Status: {scan.get('status')}")
                print(f"   Project ID: {scan.get('project_id')}")
                print(f"   Total issues: {scan.get('total_issues')}")
                print(f"   Created at: {scan.get('created_at')}")
            else:
                print("❌ No scan found with this ID")
        except Exception as e:
            print(f"❌ Error: {str(e)}")
        
        # Check scan_results table
        print("\n2️⃣ Checking scan_results table...")
        try:
            results = supabase.table("scan_results").select("*").eq("scan_id", scan_id).execute()
            if results.data:
                print(f"✅ Found {len(results.data)} scan results!")
                for i, result in enumerate(results.data[:3]):
                    print(f"\n   Result {i+1}:")
                    print(f"   - Severity: {result.get('severity')}")
                    print(f"   - Title: {result.get('title')}")
                    print(f"   - File: {result.get('file_path')}")
                if len(results.data) > 3:
                    print(f"\n   ... and {len(results.data) - 3} more results")
            else:
                print("❌ No scan results found for this scan ID")
        except Exception as e:
            print(f"❌ Error: {str(e)}")
    
    else:
        # List recent scans
        print("📋 Recent scans in database:")
        try:
            scans = supabase.table("scans").select("*").order("created_at", desc=True).limit(5).execute()
            if scans.data:
                for scan in scans.data:
                    print(f"\n   ID: {scan['id']}")
                    print(f"   Status: {scan.get('status')}")
                    print(f"   Project ID: {scan.get('project_id')}")
                    print(f"   Total issues: {scan.get('total_issues', 0)}")
                    print(f"   Created: {scan.get('created_at')}")
            else:
                print("   No scans found")
        except Exception as e:
            print(f"❌ Error: {str(e)}")

if __name__ == "__main__":
    scan_id = sys.argv[1] if len(sys.argv) > 1 else None
    test_scan_data(scan_id)