# Frontend Authentication Debug Guide

## The Issue
The error "Key (owner_id)=(00000000-0000-0000-0000-000000000000) is not present in table users" means that projects can only be created by authenticated users, which is correct behavior.

## Quick Checks

### 1. Check if you're logged in on the frontend
1. Go to https://codebase-scanner-frontend.onrender.com
2. Open browser console (F12)
3. Run these commands:

```javascript
// Check if you have a session
const session = await supabase.auth.getSession()
console.log('Session:', session)

// Check your user ID
const user = await supabase.auth.getUser()
console.log('User ID:', user.data.user?.id)
console.log('User email:', user.data.user?.email)

// Check auth token
const token = localStorage.getItem('sb-auth-token')
console.log('Auth token exists:', !!token)
```

### 2. If not logged in
You need to sign up or log in first:
1. Go to the login/signup page
2. Create an account or log in
3. Then try creating a project

### 3. Test project creation from console
Once logged in, test creating a project directly:

```javascript
// Get the auth token
const session = await supabase.auth.getSession()
const token = session.data.session?.access_token

// Test API call
const response = await fetch('https://codebase-scanner-backend-docker.onrender.com/api/projects/', {
  method: 'POST',
  headers: {
    'Authorization': `Bearer ${token}`,
    'Content-Type': 'application/json'
  },
  body: JSON.stringify({
    name: 'Test Project from Console',
    description: 'Testing authentication',
    repository_url: 'https://github.com/example/test'
  })
})

const result = await response.json()
console.log('Result:', result)
```

## Common Issues

### "Failed to fetch" error
This usually means:
1. You're not authenticated (no valid token)
2. The backend URL is wrong
3. CORS is blocking the request

### "401 Unauthorized"
- Your session has expired
- Log out and log back in

### "403 Forbidden"
- RLS policies are blocking access
- Check that the user exists in auth.users table

## Backend Environment Variables
Make sure these are set on Render:
- `SUPABASE_URL` - Your Supabase project URL
- `SUPABASE_SERVICE_ROLE_KEY` - Your service role key (not anon key!)
- `CORS_ORIGINS` - Should include https://codebase-scanner-frontend.onrender.com