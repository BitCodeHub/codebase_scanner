# Supabase Configuration Verification Checklist

## 1. Authentication Settings
Go to your Supabase Dashboard → Authentication → Providers

### ✅ Email Provider
- [ ] Email Auth is **Enabled**
- [ ] Confirm email is **Disabled** (for easier testing)
- [ ] Secure email change is **Disabled** (for easier testing)

### ✅ Site URL Configuration
Go to Authentication → URL Configuration:
- [ ] Site URL is set to: `https://codebase-scanner-frontend.onrender.com`
- [ ] Redirect URLs includes:
  - `https://codebase-scanner-frontend.onrender.com/**`
  - `https://codebase-scanner-backend.onrender.com/**`

## 2. Database Tables
Go to Table Editor and verify these tables exist:

### Required Tables:
- [ ] `projects`
- [ ] `scans`
- [ ] `scan_results`
- [ ] `reports`
- [ ] `user_profiles`

### If Tables Don't Exist:
Run this SQL in SQL Editor:
```sql
-- Check if tables exist
SELECT table_name 
FROM information_schema.tables 
WHERE table_schema = 'public' 
AND table_name IN ('projects', 'scans', 'scan_results', 'reports', 'user_profiles');
```

## 3. Row Level Security (RLS)
Check if RLS is enabled for each table:

```sql
-- Check RLS status
SELECT schemaname, tablename, rowsecurity 
FROM pg_tables 
WHERE schemaname = 'public' 
AND tablename IN ('projects', 'scans', 'scan_results', 'reports', 'user_profiles');
```

## 4. Storage Buckets
Go to Storage and verify these buckets exist:
- [ ] `project-files`
- [ ] `scan-reports`

### If Buckets Don't Exist:
```sql
-- Create storage buckets
INSERT INTO storage.buckets (id, name, public)
VALUES 
  ('project-files', 'project-files', false),
  ('scan-reports', 'scan-reports', false);
```

## 5. API Settings
Go to Settings → API:
- [ ] Note your **Project URL** (should match SUPABASE_URL)
- [ ] Note your **Anon/Public Key** (should match SUPABASE_ANON_KEY)
- [ ] Note your **Service Role Key** (should match SUPABASE_SERVICE_ROLE_KEY)

## 6. Test Authentication Directly
Open your browser console and run:
```javascript
// Test Supabase connection
const testAuth = async () => {
  const response = await fetch('https://ylllkgxzrizqlsymkybh.supabase.co/auth/v1/signup', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'apikey': 'YOUR_ANON_KEY_HERE'
    },
    body: JSON.stringify({
      email: 'test@example.com',
      password: 'TestPassword123!'
    })
  });
  console.log(await response.json());
};
testAuth();
```

## 7. Quick SQL to Create Missing Tables
If tables are missing, run this in SQL Editor:
```sql
-- Run the full schema from supabase_schema.sql
-- Or use the quick setup below:

-- Enable extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Create user_profiles if missing
CREATE TABLE IF NOT EXISTS user_profiles (
    id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
    email VARCHAR(255),
    full_name VARCHAR(255),
    avatar_url VARCHAR(500),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Enable RLS
ALTER TABLE user_profiles ENABLE ROW LEVEL SECURITY;

-- Create policy for users to see their own profile
CREATE POLICY "Users can view own profile" ON user_profiles
    FOR SELECT USING (auth.uid() = id);

CREATE POLICY "Users can update own profile" ON user_profiles
    FOR UPDATE USING (auth.uid() = id);

CREATE POLICY "Users can insert own profile" ON user_profiles
    FOR INSERT WITH CHECK (auth.uid() = id);
```

## 8. Environment Variables to Double-Check
In Render Dashboard → Environment Groups → CodeScanner:
- [ ] `SUPABASE_URL` = `https://ylllkgxzrizqlsymkybh.supabase.co`
- [ ] `SUPABASE_ANON_KEY` = starts with `eyJhbGciOiJIUzI1NiIs...`
- [ ] `SUPABASE_SERVICE_ROLE_KEY` = starts with `eyJhbGciOiJIUzI1NiIs...`
- [ ] `VITE_SUPABASE_URL` = same as SUPABASE_URL
- [ ] `VITE_SUPABASE_ANON_KEY` = same as SUPABASE_ANON_KEY

## 9. Common Issues and Fixes

### "Supabase not configured"
- Frontend hasn't rebuilt with env vars
- Check browser console for configuration log

### "Email not confirmed"
- Disable email confirmation in Auth settings
- Or check email for confirmation link

### "Invalid API key"
- Verify the anon key matches exactly
- No extra spaces or characters

### "Network error"
- Check CORS settings
- Verify Site URL configuration