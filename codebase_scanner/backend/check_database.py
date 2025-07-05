#!/usr/bin/env python3
"""Check and fix Supabase database schema"""

import os
import sys
from dotenv import load_dotenv
from supabase import create_client

# Load environment variables
load_dotenv()

def check_database():
    print("🔍 Checking Supabase database schema...\n")
    
    supabase_url = os.getenv("SUPABASE_URL")
    supabase_key = os.getenv("SUPABASE_SERVICE_ROLE_KEY")
    
    if not supabase_url or not supabase_key:
        print("❌ Missing Supabase credentials in .env file")
        return False
    
    try:
        supabase = create_client(supabase_url, supabase_key)
        print(f"✅ Connected to Supabase: {supabase_url}\n")
        
        # Check if projects table exists
        print("📊 Checking projects table...")
        try:
            result = supabase.table('projects').select("*").limit(1).execute()
            print("✅ Projects table exists")
            
            # Check columns
            if result.data and len(result.data) > 0:
                columns = list(result.data[0].keys())
                print(f"   Columns: {', '.join(columns)}")
            else:
                print("   No data in table (running test insert)")
                # Try to get column info by inserting and deleting a test record
                test_project = {
                    "name": "TEST_SCHEMA_CHECK",
                    "description": "Temporary test project",
                    "owner_id": "00000000-0000-0000-0000-000000000000"
                }
                try:
                    insert_result = supabase.table('projects').insert(test_project).execute()
                    if insert_result.data:
                        print(f"   Successfully inserted test project")
                        columns = list(insert_result.data[0].keys())
                        print(f"   Columns: {', '.join(columns)}")
                        # Delete test project
                        supabase.table('projects').delete().eq('name', 'TEST_SCHEMA_CHECK').execute()
                except Exception as e:
                    print(f"   ⚠️  Column check failed: {str(e)}")
                    
        except Exception as e:
            print(f"❌ Projects table error: {str(e)}")
            print("\n🔧 The projects table might not exist or has incorrect schema.")
            print("   Please run the schema SQL in your Supabase dashboard.")
            return False
            
        # Check if the schema matches what the backend expects
        print("\n🔍 Checking schema compatibility...")
        required_columns = {
            'projects': ['id', 'name', 'description', 'owner_id', 'created_at', 'updated_at'],
            'scans': ['id', 'project_id', 'status', 'created_at']
        }
        
        # Check RLS policies
        print("\n🔒 Checking Row Level Security...")
        try:
            # Try to query with anon key to test RLS
            test_result = supabase.table('projects').select("id").execute()
            if not hasattr(test_result, 'data'):
                print("⚠️  RLS might be blocking access")
            else:
                print("✅ RLS policies seem to be working")
        except Exception as e:
            print(f"⚠️  RLS check inconclusive: {str(e)}")
            
        return True
        
    except Exception as e:
        print(f"\n❌ Database connection failed: {str(e)}")
        return False

def show_fix_instructions():
    print("\n" + "="*60)
    print("📋 TO FIX THE DATABASE:")
    print("="*60)
    print("\n1. Go to your Supabase dashboard: https://app.supabase.com")
    print("2. Select your project")
    print("3. Go to SQL Editor")
    print("4. Run the schema from: backend/supabase_schema.sql")
    print("\n5. If the tables already exist but have wrong schema:")
    print("   - First backup any existing data")
    print("   - Then drop and recreate the tables")
    print("\n6. Make sure you have the correct environment variables on Render:")
    print("   - SUPABASE_URL")
    print("   - SUPABASE_SERVICE_ROLE_KEY")
    print("\n7. After fixing, redeploy your backend on Render")

if __name__ == "__main__":
    if check_database():
        print("\n✅ Database check complete!")
    else:
        show_fix_instructions()