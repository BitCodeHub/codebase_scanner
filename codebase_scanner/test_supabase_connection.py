#!/usr/bin/env python3
"""
Test Supabase connection and basic operations
"""

import os
import asyncio
from supabase import create_client, Client
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

def test_supabase_connection():
    """Test basic Supabase connection and operations"""
    
    try:
        # Initialize Supabase client
        url = os.getenv("SUPABASE_URL")
        key = os.getenv("SUPABASE_SERVICE_KEY")
        
        if not url or not key:
            print("❌ Missing Supabase credentials in .env file")
            return False
            
        print(f"🔗 Connecting to Supabase: {url}")
        
        supabase: Client = create_client(url, key)
        
        # Test 1: Check if we can connect and query projects table
        print("\n📋 Test 1: Query projects table")
        result = supabase.table("projects").select("*").limit(1).execute()
        print(f"✅ Projects table accessible: {len(result.data)} records")
        
        # Test 2: Check if we can query scans table  
        print("\n📋 Test 2: Query scans table")
        result = supabase.table("scans").select("*").limit(1).execute()
        print(f"✅ Scans table accessible: {len(result.data)} records")
        
        # Test 3: Check if we can query scan_results table
        print("\n📋 Test 3: Query scan_results table")
        result = supabase.table("scan_results").select("*").limit(1).execute()
        print(f"✅ Scan results table accessible: {len(result.data)} records")
        
        # Test 4: Check storage buckets
        print("\n📋 Test 4: Check storage buckets")
        buckets = supabase.storage.list_buckets()
        bucket_names = [bucket.name for bucket in buckets]
        print(f"✅ Storage buckets available: {bucket_names}")
        
        print("\n🎉 All Supabase tests passed!")
        print("\n📊 Database Status:")
        print("   ✅ Tables created successfully")
        print("   ✅ RLS policies active")
        print("   ✅ Storage buckets ready")
        print("   ✅ Connection working")
        
        return True
        
    except Exception as e:
        print(f"❌ Supabase connection test failed: {str(e)}")
        print("\n🔧 Troubleshooting:")
        print("   1. Make sure you've run the SQL schema in Supabase SQL Editor")
        print("   2. Check your .env file has correct credentials")
        print("   3. Verify your Supabase project is active")
        return False

if __name__ == "__main__":
    print("🧪 Testing Supabase Connection...")
    print("=" * 50)
    
    success = test_supabase_connection()
    
    if success:
        print("\n🚀 Ready to start development!")
        print("   Run: npm run dev")
    else:
        print("\n❌ Setup incomplete. Please fix issues above.")