#!/usr/bin/env python3
"""Test the API directly to debug project creation issues"""

import os
import asyncio
from dotenv import load_dotenv
from supabase import create_client
from datetime import datetime

# Load environment variables
load_dotenv()

async def test_api():
    print("🔍 Testing direct database operations...\n")
    
    supabase_url = os.getenv("SUPABASE_URL")
    supabase_key = os.getenv("SUPABASE_SERVICE_ROLE_KEY")
    
    if not supabase_url or not supabase_key:
        print("❌ Missing Supabase credentials")
        return
    
    supabase = create_client(supabase_url, supabase_key)
    
    # Test 1: Check table schema
    print("1️⃣ Checking projects table schema...")
    try:
        # Get column information
        result = supabase.rpc('get_table_columns', {'table_name': 'projects'}).execute()
        print("   Columns via RPC:", result.data if hasattr(result, 'data') else "RPC not available")
    except:
        print("   (RPC method not available, trying direct query)")
    
    # Test 2: Try to create a project
    print("\n2️⃣ Testing project creation...")
    test_project = {
        "name": f"API Test {datetime.now().strftime('%Y%m%d_%H%M%S')}",
        "description": "Testing direct API",
        "github_repo_url": "https://github.com/test/repo",
        "owner_id": "00000000-0000-0000-0000-000000000000",
        "language": "Python",
        "framework": "FastAPI",
        "is_active": True,
        "created_at": datetime.utcnow().isoformat(),
        "updated_at": datetime.utcnow().isoformat()
    }
    
    try:
        result = supabase.table('projects').insert(test_project).execute()
        if result.data:
            print("   ✅ Project created successfully!")
            print(f"   ID: {result.data[0]['id']}")
            print(f"   Fields returned: {list(result.data[0].keys())}")
            
            # Clean up test project
            project_id = result.data[0]['id']
            supabase.table('projects').delete().eq('id', project_id).execute()
            print("   🧹 Test project cleaned up")
        else:
            print("   ❌ No data returned from insert")
    except Exception as e:
        print(f"   ❌ Insert failed: {str(e)}")
        if "column" in str(e).lower():
            print("\n   ⚠️  Missing columns detected!")
            print("   Please run fix_database.sql in your Supabase SQL Editor")
    
    # Test 3: Check if we can query projects
    print("\n3️⃣ Testing project query...")
    try:
        result = supabase.table('projects').select("*").limit(5).execute()
        print(f"   ✅ Query successful, found {len(result.data)} projects")
        if result.data:
            print(f"   First project columns: {list(result.data[0].keys())}")
    except Exception as e:
        print(f"   ❌ Query failed: {str(e)}")

if __name__ == "__main__":
    asyncio.run(test_api())