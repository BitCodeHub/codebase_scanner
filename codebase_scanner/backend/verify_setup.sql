-- Verify your Supabase setup is complete
-- Run each section in your Supabase SQL Editor

-- 1. Check if projects table has all required columns
SELECT 
    '✅ Column exists: ' || column_name as status,
    column_name, 
    data_type,
    CASE 
        WHEN column_name IN ('language', 'framework') THEN '⭐ NEW COLUMN'
        ELSE 'Original'
    END as notes
FROM information_schema.columns 
WHERE table_schema = 'public' 
AND table_name = 'projects'
ORDER BY 
    CASE 
        WHEN column_name IN ('language', 'framework') THEN 0
        ELSE 1
    END,
    ordinal_position;

-- 2. Check if you have any users in the system
SELECT 
    COUNT(*) as total_users,
    CASE 
        WHEN COUNT(*) > 0 THEN '✅ Users exist in the system'
        ELSE '❌ No users found - you need to sign up first!'
    END as status
FROM auth.users;

-- 3. Check if you have any projects
SELECT 
    COUNT(*) as total_projects,
    CASE 
        WHEN COUNT(*) > 0 THEN '✅ Projects exist'
        ELSE '⚠️  No projects yet - this is normal if you just set up'
    END as status
FROM projects;

-- 4. Check Row Level Security status
SELECT 
    schemaname,
    tablename,
    CASE 
        WHEN rowsecurity THEN '✅ RLS Enabled'
        ELSE '❌ RLS Disabled - Security Risk!'
    END as rls_status
FROM pg_tables
WHERE schemaname = 'public'
AND tablename IN ('projects', 'scans', 'scan_results');

-- 5. Test if your user can create projects (replace with your actual user ID)
-- First, get your user ID:
SELECT 
    id as user_id,
    email,
    created_at,
    '👆 Copy this user ID for testing' as note
FROM auth.users
LIMIT 5;