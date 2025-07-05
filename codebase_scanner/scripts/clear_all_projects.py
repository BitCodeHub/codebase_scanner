#!/usr/bin/env python3
"""
Clear all projects and associated data from the database
"""

import os
import sys
from datetime import datetime

# Add the backend directory to the path
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'backend'))
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'backend', 'src'))

from dotenv import load_dotenv
from src.database import get_supabase_client

# Load environment variables
load_dotenv()

def clear_all_projects():
    """Clear all projects and associated data"""
    
    # Get Supabase client using the backend's method
    supabase = get_supabase_client()
    
    print("🗑️  CLEARING ALL PROJECTS AND ASSOCIATED DATA")
    print("=" * 50)
    
    try:
        # First, get count of existing data
        projects_count = len(supabase.table('projects').select('id').execute().data)
        scans_count = len(supabase.table('scans').select('id').execute().data)
        scan_results_count = len(supabase.table('scan_results').select('id').execute().data)
        
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
        if scan_results_count > 0:
            print("   - Deleting scan results...", end="", flush=True)
            supabase.table('scan_results').delete().neq('id', 0).execute()
            print(" ✅")
        
        # 2. Delete all scans
        if scans_count > 0:
            print("   - Deleting scans...", end="", flush=True)
            supabase.table('scans').delete().neq('id', 0).execute()
            print(" ✅")
        
        # 3. Delete all projects
        if projects_count > 0:
            print("   - Deleting projects...", end="", flush=True)
            supabase.table('projects').delete().neq('id', 0).execute()
            print(" ✅")
        
        # Verify deletion
        print("\n📊 Verifying deletion...")
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
        print(f"\n❌ Error clearing data: {str(e)}")
        print("   You may need to use the service role key for full delete permissions")

if __name__ == "__main__":
    clear_all_projects()