#!/usr/bin/env python3
"""
Simple script to clear all projects and associated data from the database
"""

import os
from datetime import datetime

# Try different ways to import supabase
try:
    # Method 1: Try newer version without proxy
    from supabase import create_client
    
    def get_client(url, key):
        try:
            return create_client(url, key)
        except TypeError:
            # If proxy error, try without options
            from supabase._sync.client import SyncClient
            return SyncClient(supabase_url=url, supabase_key=key)
except ImportError:
    print("❌ Please install supabase: pip install supabase")
    exit(1)

from dotenv import load_dotenv

# Load environment variables
load_dotenv()

def clear_all_projects():
    """Clear all projects and associated data"""
    
    # Get Supabase credentials
    supabase_url = os.getenv('SUPABASE_URL')
    supabase_key = os.getenv('SUPABASE_SERVICE_ROLE_KEY') or os.getenv('SUPABASE_ANON_KEY')
    
    if not supabase_url or not supabase_key:
        print("❌ Missing Supabase credentials. Please set SUPABASE_URL and SUPABASE_ANON_KEY")
        print(f"   SUPABASE_URL: {'✅ Set' if supabase_url else '❌ Missing'}")
        print(f"   SUPABASE_KEY: {'✅ Set' if supabase_key else '❌ Missing'}")
        return
    
    print("🔄 Connecting to Supabase...")
    
    try:
        # Create Supabase client
        supabase = get_client(supabase_url, supabase_key)
        
        print("✅ Connected to Supabase")
        print("\n🗑️  CLEARING ALL PROJECTS AND ASSOCIATED DATA")
        print("=" * 50)
        
        # First, get count of existing data
        try:
            projects_count = len(supabase.table('projects').select('id').execute().data)
            scans_count = len(supabase.table('scans').select('id').execute().data)
            scan_results_count = len(supabase.table('scan_results').select('id').execute().data)
        except Exception as e:
            print(f"❌ Error getting counts: {e}")
            projects_count = scans_count = scan_results_count = "Unknown"
        
        print(f"📊 Current data:")
        print(f"   - Projects: {projects_count}")
        print(f"   - Scans: {scans_count}")
        print(f"   - Scan Results: {scan_results_count}")
        print()
        
        if projects_count == 0 and scans_count == 0 and scan_results_count == 0:
            print("✅ Database is already empty!")
            return
        
        # Confirm deletion
        print("⚠️  WARNING: This will permanently delete all data!")
        confirm = input("Type 'DELETE ALL' to confirm: ")
        
        if confirm != 'DELETE ALL':
            print("❌ Deletion cancelled")
            return
        
        print("\n🔄 Deleting data...")
        
        # Delete in order to respect foreign key constraints
        # 1. Delete all scan results first
        try:
            print("   - Deleting scan results...", end="", flush=True)
            result = supabase.table('scan_results').delete().neq('id', 0).execute()
            print(f" ✅ ({len(result.data) if hasattr(result, 'data') else 'Done'})")
        except Exception as e:
            print(f" ⚠️  Warning: {e}")
        
        # 2. Delete all scans
        try:
            print("   - Deleting scans...", end="", flush=True)
            result = supabase.table('scans').delete().neq('id', 0).execute()
            print(f" ✅ ({len(result.data) if hasattr(result, 'data') else 'Done'})")
        except Exception as e:
            print(f" ⚠️  Warning: {e}")
        
        # 3. Delete all projects
        try:
            print("   - Deleting projects...", end="", flush=True)
            result = supabase.table('projects').delete().neq('id', 0).execute()
            print(f" ✅ ({len(result.data) if hasattr(result, 'data') else 'Done'})")
        except Exception as e:
            print(f" ⚠️  Warning: {e}")
        
        # Verify deletion
        print("\n📊 Verifying deletion...")
        try:
            projects_after = len(supabase.table('projects').select('id').execute().data)
            scans_after = len(supabase.table('scans').select('id').execute().data)
            scan_results_after = len(supabase.table('scan_results').select('id').execute().data)
            
            print(f"   - Projects remaining: {projects_after}")
            print(f"   - Scans remaining: {scans_after}")
            print(f"   - Scan Results remaining: {scan_results_after}")
            
            if projects_after == 0 and scans_after == 0 and scan_results_after == 0:
                print("\n✅ All data successfully cleared!")
                print(f"   Completed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            else:
                print("\n⚠️  Some data may not have been deleted. Please check manually.")
        except Exception as e:
            print(f"\n⚠️  Could not verify deletion: {e}")
            print("   Data may have been deleted successfully.")
        
    except Exception as e:
        print(f"\n❌ Error: {str(e)}")
        print("\n💡 Alternative: You can also clear data using the Supabase dashboard:")
        print("   1. Go to your Supabase project dashboard")
        print("   2. Navigate to Table Editor")
        print("   3. Select each table (scan_results, scans, projects)")
        print("   4. Click 'Select all' and then 'Delete rows'")

if __name__ == "__main__":
    clear_all_projects()