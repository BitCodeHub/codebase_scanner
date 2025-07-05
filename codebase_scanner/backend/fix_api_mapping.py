#!/usr/bin/env python3
"""Fix API field mapping for projects table"""

import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

print("🔧 Checking API field mapping...\n")

# The schema shows these columns in projects table:
schema_columns = [
    "id",                    # BIGSERIAL PRIMARY KEY
    "name",                  # VARCHAR(255) NOT NULL
    "description",           # TEXT
    "github_repo_url",       # VARCHAR(500) <- Different from API!
    "github_default_branch", # VARCHAR(100) <- Not in API
    "uploaded_file_path",    # VARCHAR(500) <- Not in API
    "owner_id",             # UUID
    "created_at",           # TIMESTAMPTZ
    "updated_at",           # TIMESTAMPTZ
    "is_active"             # BOOLEAN <- Different from API!
]

# The API expects these fields:
api_fields = [
    "id",
    "name", 
    "description",
    "repository_url",        # <- Maps to github_repo_url
    "language",             # <- Not in schema!
    "framework",            # <- Not in schema!
    "active",               # <- Maps to is_active
    "created_at",
    "updated_at"
]

print("📊 Schema vs API field mapping issues found:\n")
print("1. Schema has 'github_repo_url' but API uses 'repository_url'")
print("2. Schema has 'is_active' but API uses 'active'")
print("3. API expects 'language' and 'framework' but they're not in schema")
print("4. Schema has extra fields: 'github_default_branch', 'uploaded_file_path'")

print("\n🔧 Creating migration script...")

migration_sql = """
-- Add missing columns to projects table
ALTER TABLE projects ADD COLUMN IF NOT EXISTS language VARCHAR(100);
ALTER TABLE projects ADD COLUMN IF NOT EXISTS framework VARCHAR(100);

-- Create a view that maps the columns to match the API
CREATE OR REPLACE VIEW projects_api AS
SELECT 
    id,
    name,
    description,
    github_repo_url as repository_url,
    language,
    framework,
    is_active as active,
    owner_id,
    created_at,
    updated_at
FROM projects;

-- Enable RLS on the view
ALTER VIEW projects_api SET (security_invoker = true);

-- Create RLS policies for the view (if needed)
-- The view will inherit the policies from the base table
"""

with open("fix_database_mapping.sql", "w") as f:
    f.write(migration_sql)
    
print("\n✅ Created fix_database_mapping.sql")
print("\n📋 To fix the issue:")
print("1. Go to Supabase SQL Editor")
print("2. Run the contents of fix_database_mapping.sql")
print("3. Update the backend to use 'projects_api' view instead of 'projects' table")
print("\nOR update the backend code to use the correct column names.")