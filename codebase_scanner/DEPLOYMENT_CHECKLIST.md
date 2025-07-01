# Deployment Checklist for Codebase Scanner

## Backend Environment Variables (Required on Render)

1. **SUPABASE_URL** - Your Supabase project URL
2. **SUPABASE_SERVICE_ROLE_KEY** - Service role key (not anon key)
3. **SUPABASE_ANON_KEY** - Anon key for public operations
4. **CORS_ORIGINS** - Frontend URL (e.g., "https://codebase-scanner-frontend.onrender.com")
5. **PYTHON_VERSION** - Set to "3.11"
6. **REDIS_URL** - Provided by Render Redis service

## Frontend Environment Variables (Required on Render)

1. **VITE_SUPABASE_URL** - Same as backend SUPABASE_URL
2. **VITE_SUPABASE_ANON_KEY** - Same as backend SUPABASE_ANON_KEY
3. **VITE_API_URL** - Backend URL (e.g., "https://codebase-scanner-backend.onrender.com")
4. **NODE_VERSION** - Set to "20"

## Debugging Steps

### 1. Test Backend Health
```bash
curl https://codebase-scanner-backend.onrender.com/health
```

### 2. Test Supabase Connection
```bash
curl https://codebase-scanner-backend.onrender.com/api/supabase/test
```

### 3. Access Debug Page
Navigate to: https://codebase-scanner-frontend.onrender.com/debug

### 4. Common Issues and Fixes

#### "Failed to create project"
- Check if SUPABASE_SERVICE_ROLE_KEY is set correctly
- Verify CORS_ORIGINS includes frontend URL
- Check backend logs for authentication errors

#### "Failed to fetch"
- Ensure backend is running (check Render dashboard)
- Verify VITE_API_URL points to correct backend URL
- Check CORS configuration

#### Authentication Issues
- Ensure both frontend and backend use same Supabase project
- Service role key should be used in backend, anon key in frontend
- Check if user is properly authenticated before API calls

## Database Schema Requirements

The following tables must exist in Supabase:

1. **projects**
   - id (uuid, primary key)
   - owner_id (uuid, references auth.users)
   - name (text)
   - description (text, nullable)
   - github_repo_url (text, nullable)
   - is_active (boolean, default true)
   - created_at (timestamp)
   - updated_at (timestamp)

2. **scans**
   - id (uuid, primary key)
   - project_id (uuid, references projects)
   - user_id (uuid, references auth.users)
   - scan_type (text)
   - status (text)
   - triggered_by (text)
   - scan_config (jsonb, nullable)
   - started_at (timestamp, nullable)
   - completed_at (timestamp, nullable)
   - created_at (timestamp)
   - updated_at (timestamp)

3. **scan_results**
   - id (uuid, primary key)
   - scan_id (uuid, references scans)
   - rule_id (text)
   - title (text)
   - description (text)
   - severity (text)
   - category (text)
   - vulnerability_type (text)
   - file_path (text)
   - line_number (integer)
   - code_snippet (text, nullable)
   - confidence (text)
   - owasp_category (text, nullable)
   - fix_recommendation (text, nullable)
   - cvss_score (numeric, nullable)
   - created_at (timestamp)

## Testing the Full Flow

1. **Register/Login**: Create account or login at frontend URL
2. **Create Project**: Use debug page to test project creation
3. **Check Backend Logs**: Monitor Render logs for errors
4. **Verify Database**: Check Supabase dashboard for created records