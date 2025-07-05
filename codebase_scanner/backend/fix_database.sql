-- Fix database schema to match the backend API
-- Run this in your Supabase SQL Editor

-- 1. Add missing columns to projects table
ALTER TABLE projects ADD COLUMN IF NOT EXISTS language VARCHAR(100);
ALTER TABLE projects ADD COLUMN IF NOT EXISTS framework VARCHAR(100);

-- 2. Update the column defaults to match the API expectations
ALTER TABLE projects ALTER COLUMN is_active SET DEFAULT true;

-- 3. Create a test to verify the schema is correct
DO $$
BEGIN
    -- Check if all required columns exist
    IF EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'projects' 
        AND column_name IN ('id', 'name', 'description', 'github_repo_url', 'owner_id', 'created_at', 'updated_at', 'is_active', 'language', 'framework')
        GROUP BY table_name 
        HAVING COUNT(*) = 10
    ) THEN
        RAISE NOTICE 'Success: All required columns exist in projects table';
    ELSE
        RAISE WARNING 'Error: Some columns are missing from projects table';
    END IF;
END $$;

-- 4. Test insert to verify everything works
-- This will be rolled back, just for testing
BEGIN;
INSERT INTO projects (name, description, github_repo_url, owner_id, language, framework)
VALUES (
    'Test Project Schema', 
    'This is a test to verify schema', 
    'https://github.com/test/repo',
    '00000000-0000-0000-0000-000000000000'::uuid,
    'TypeScript',
    'React'
);
ROLLBACK;

-- If the above runs without errors, your schema is fixed!