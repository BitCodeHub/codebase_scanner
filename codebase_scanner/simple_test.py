#!/usr/bin/env python3
"""
Simple test to verify setup
"""

import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

def check_environment():
    """Check if environment variables are set"""
    
    print("🔍 Checking Environment Variables...")
    
    required_vars = [
        "SUPABASE_URL",
        "SUPABASE_ANON_KEY", 
        "SUPABASE_SERVICE_KEY",
        "VITE_SUPABASE_URL",
        "VITE_SUPABASE_ANON_KEY"
    ]
    
    all_good = True
    
    for var in required_vars:
        value = os.getenv(var)
        if value:
            # Hide sensitive parts
            display_value = value[:10] + "..." if len(value) > 10 else value
            print(f"✅ {var}: {display_value}")
        else:
            print(f"❌ {var}: Not set")
            all_good = False
    
    return all_good

def check_project_structure():
    """Check if project files exist"""
    
    print("\n📁 Checking Project Structure...")
    
    files_to_check = [
        "frontend/package.json",
        "backend/app/main.py",
        "backend/app/database.py",
        ".env",
        "supabase_schema.sql"
    ]
    
    all_exist = True
    
    for file_path in files_to_check:
        if os.path.exists(file_path):
            print(f"✅ {file_path}")
        else:
            print(f"❌ {file_path}")
            all_exist = False
    
    return all_exist

if __name__ == "__main__":
    print("🧪 Testing Basic Setup...")
    print("=" * 50)
    
    env_ok = check_environment()
    structure_ok = check_project_structure()
    
    if env_ok and structure_ok:
        print("\n🎉 Basic setup looks good!")
        print("\n📋 Next Steps:")
        print("1. 🗄️ Go to your Supabase dashboard:")
        print(f"   {os.getenv('SUPABASE_URL')}")
        print("2. 📝 Run the SQL schema (copy from supabase_schema.sql)")
        print("3. 🚀 Start development servers:")
        print("   Frontend: cd frontend && npm run dev")
        print("   Backend:  cd backend && python3 -m uvicorn app.main:app --reload")
    else:
        print("\n❌ Setup issues found. Please fix the missing items above.")