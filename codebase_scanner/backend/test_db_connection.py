#!/usr/bin/env python3
"""Test Supabase database connection"""

import os
import sys
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

def test_connection():
    print("🔍 Testing Supabase connection...\n")
    
    # Check if credentials exist
    supabase_url = os.getenv("SUPABASE_URL")
    supabase_key = os.getenv("SUPABASE_SERVICE_ROLE_KEY")
    
    if not supabase_url or supabase_url == "https://your-project.supabase.co":
        print("❌ SUPABASE_URL not configured")
        print("   Please add your Supabase URL to .env file")
        return False
        
    if not supabase_key or supabase_key == "your-service-role-key":
        print("❌ SUPABASE_SERVICE_ROLE_KEY not configured")
        print("   Please add your service role key to .env file")
        return False
    
    print(f"✅ Supabase URL: {supabase_url}")
    print(f"✅ Service key: {supabase_key[:10]}...")
    
    # Try to connect
    try:
        from supabase import create_client
        
        supabase = create_client(supabase_url, supabase_key)
        
        # Test query
        print("\n🔄 Testing database query...")
        result = supabase.table('projects').select("id").limit(1).execute()
        
        print("✅ Database connection successful!")
        print(f"   Projects table accessible")
        
        # Try to get user count
        try:
            user_result = supabase.auth.admin.list_users()
            print(f"   Total users: {len(user_result)}")
        except:
            print("   (User count requires admin permissions)")
            
        return True
        
    except Exception as e:
        print(f"\n❌ Connection failed: {str(e)}")
        return False

if __name__ == "__main__":
    print("="*50)
    print("Supabase Connection Test")
    print("="*50)
    
    if test_connection():
        print("\n✅ All tests passed! Your backend is ready to save projects.")
    else:
        print("\n❌ Connection failed. Please check your credentials.")
        print("\nNeed help? Check the setup guide in SETUP_GUIDE.md")