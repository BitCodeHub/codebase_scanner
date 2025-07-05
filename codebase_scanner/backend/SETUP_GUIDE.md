# 🚨 Backend Setup Guide - Fix Projects Not Saving

## Problem
Your projects aren't being saved because the backend is missing Supabase database credentials. Without these credentials, the API uses temporary in-memory storage that doesn't persist.

## Quick Fix (5 minutes)

### 1. Create the .env file
```bash
cd backend
./setup_env.sh
```

### 2. Get your Supabase credentials
1. Go to https://app.supabase.com
2. Select your project (or create one if needed)
3. Go to **Settings → API**
4. Copy these values:
   - **Project URL** (looks like: https://abcdefghijk.supabase.co)
   - **service_role key** (starts with: eyJ...)

### 3. Add credentials to .env
Edit the `.env` file and replace the placeholder values:
```env
SUPABASE_URL=https://your-actual-project.supabase.co
SUPABASE_SERVICE_ROLE_KEY=eyJ...your-actual-service-role-key...
```

### 4. Test the connection
```bash
python test_db_connection.py
```

You should see:
```
✅ Supabase URL: https://your-project.supabase.co
✅ Service key: eyJ...
✅ Database connection successful!
```

### 5. Deploy to Render
Since your backend is on Render, you need to add these environment variables there too:

1. Go to your Render dashboard
2. Select your backend service (codebase-scanner-backend-docker)
3. Go to **Environment** tab
4. Add these environment variables:
   - `SUPABASE_URL` = your Supabase URL
   - `SUPABASE_SERVICE_ROLE_KEY` = your service role key
5. Click **Save Changes** - this will trigger a redeploy

## Verify It's Working

### Frontend Test
1. Go to your frontend: https://codebase-scanner-frontend.onrender.com
2. Click "Create New Project"
3. Fill in the form and submit
4. The project should now appear in your list!

### Backend Health Check
Visit: https://codebase-scanner-backend-docker.onrender.com/health

You should see:
```json
{
  "status": "healthy",
  "service": "codebase-scanner-api"
}
```

## Still Having Issues?

### Check the logs
```bash
# Local testing
cd backend
python -m uvicorn app.main:app --reload

# On Render
# Go to your service dashboard → Logs tab
```

### Common issues:
1. **Wrong credentials**: Double-check you copied the service_role key, not the anon key
2. **CORS errors**: Make sure your frontend URL is in the CORS_ORIGINS in .env
3. **Backend not redeployed**: After adding env vars on Render, make sure it redeployed

## API Test
Once configured, test the API directly:
```bash
# Get your auth token from browser console:
# 1. Go to frontend and login
# 2. Open browser console (F12)
# 3. Run: localStorage.getItem('sb-auth-token')
# 4. Copy the access_token value

# Test project creation
curl -X POST https://codebase-scanner-backend-docker.onrender.com/api/projects/ \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Test Project",
    "description": "Testing API",
    "repository_url": "https://github.com/example/repo"
  }'
```

## Success! 🎉
Once you've added the Supabase credentials, your projects will be saved to the database and persist across sessions.