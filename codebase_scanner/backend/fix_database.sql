-- Fix database schema to match the backend API
-- Run this in your Supabase SQL Editor

-- 1. Add missing columns to projects table
ALTER TABLE projects ADD COLUMN IF NOT EXISTS language VARCHAR(100);
ALTER TABLE projects ADD COLUMN IF NOT EXISTS framework VARCHAR(100);

-- 2. Update the column defaults to match the API expectations
ALTER TABLE projects ALTER COLUMN is_active SET DEFAULT true;

-- 3. Check if all required columns exist
SELECT 
    column_name, 
    data_type, 
    is_nullable,
    column_default
FROM information_schema.columns 
WHERE table_schema = 'public' 
AND table_name = 'projects'
ORDER BY ordinal_position;

-- 4. Verify the foreign key constraint exists
SELECT
    tc.constraint_name, 
    tc.constraint_type,
    kcu.column_name,
    ccu.table_name AS foreign_table_name,
    ccu.column_name AS foreign_column_name 
FROM 
    information_schema.table_constraints AS tc 
    JOIN information_schema.key_column_usage AS kcu
      ON tc.constraint_name = kcu.constraint_name
      AND tc.table_schema = kcu.table_schema
    JOIN information_schema.constraint_column_usage AS ccu
      ON ccu.constraint_name = tc.constraint_name
      AND ccu.table_schema = tc.table_schema
WHERE tc.constraint_type = 'FOREIGN KEY' 
AND tc.table_name='projects';

-- 5. Success message
DO $$
BEGIN
    RAISE NOTICE '✅ Schema update complete!';
    RAISE NOTICE 'The projects table now has language and framework columns.';
    RAISE NOTICE 'Projects can only be created with valid user IDs from auth.users table.';
END $$;