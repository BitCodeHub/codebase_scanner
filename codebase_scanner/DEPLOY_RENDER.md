# Deployment Guide for Render

This guide will help you deploy the CodeScan Security Scanner to Render.com.

## Prerequisites

1. A Render account (sign up at https://render.com)
2. A Supabase project with the database schema set up
3. An Anthropic API key for AI-powered vulnerability analysis

## Deployment Steps

### 1. Fork or Push to GitHub

Ensure your code is in a GitHub repository that Render can access.

### 2. Create Services on Render

You can deploy using the render.yaml file (Infrastructure as Code) or manually create services.

#### Option A: Deploy with render.yaml (Recommended)

1. Connect your GitHub repository to Render
2. Go to the Render Dashboard
3. Click "New" → "Blueprint"
4. Connect your repository and select the branch
5. Render will detect the render.yaml and create all services

#### Option B: Manual Service Creation

Create the following services in order:

1. **PostgreSQL Database** (if not using Supabase)
   - Name: `codebase-scanner-db`
   - Plan: Free

2. **Redis Instance**
   - Name: `codebase-scanner-redis`
   - Plan: Free
   - Maxmemory Policy: allkeys-lru

3. **Backend API Service**
   - Type: Web Service
   - Name: `codebase-scanner-backend`
   - Runtime: Python 3.11
   - Build Command: `pip install -r requirements.txt`
   - Start Command: `cd backend && python -m uvicorn app.main:app --host 0.0.0.0 --port $PORT`
   - Plan: Free

4. **Background Worker**
   - Type: Background Worker
   - Name: `codebase-scanner-worker`
   - Runtime: Python 3.11
   - Build Command: `pip install -r requirements.txt`
   - Start Command: `cd backend && celery -A app.celery_app worker --loglevel=info`
   - Plan: Free

5. **Frontend Static Site**
   - Type: Static Site
   - Name: `codebase-scanner-frontend`
   - Build Command: `cd frontend && npm install && npm run build`
   - Publish Directory: `./frontend/dist`
   - Plan: Free

### 3. Configure Environment Variables

For each service, add the required environment variables:

#### Backend API & Worker Services:
```
SUPABASE_URL=your_supabase_project_url
SUPABASE_SERVICE_ROLE_KEY=your_supabase_service_role_key
SUPABASE_ANON_KEY=your_supabase_anon_key
ANTHROPIC_API_KEY=your_anthropic_api_key
CORS_ORIGINS=https://codebase-scanner-frontend.onrender.com,http://localhost:5173
```

Note: REDIS_URL and DATABASE_URL will be automatically set by Render when you link the services.

#### Frontend Static Site:
```
VITE_SUPABASE_URL=your_supabase_project_url
VITE_SUPABASE_ANON_KEY=your_supabase_anon_key
VITE_API_URL=https://codebase-scanner-backend.onrender.com
```

### 4. Set Up Supabase

1. Create a new Supabase project at https://supabase.com
2. Run the schema SQL file in your Supabase SQL editor:
   - Go to SQL Editor in Supabase Dashboard
   - Create a new query
   - Copy contents from `supabase_schema.sql`
   - Run the query

3. Configure Row Level Security (RLS):
   - Enable RLS on all tables
   - Add appropriate policies (see `supabase_schema.sql`)

4. Get your API keys:
   - Project URL: Settings → API → Project URL
   - Anon Key: Settings → API → Project API keys → anon/public
   - Service Role Key: Settings → API → Project API keys → service_role

### 5. Configure Authentication

In Supabase:
1. Go to Authentication → Providers
2. Enable Email authentication
3. (Optional) Enable GitHub OAuth:
   - Create a GitHub OAuth App
   - Add callback URL: `https://your-project.supabase.co/auth/v1/callback`
   - Add the Client ID and Secret to Supabase

### 6. Post-Deployment Steps

1. **Test the Frontend**
   - Visit: `https://codebase-scanner-frontend.onrender.com`
   - You should see the login page

2. **Test the Backend**
   - Visit: `https://codebase-scanner-backend.onrender.com/docs`
   - You should see the FastAPI documentation

3. **Create a Test Account**
   - Sign up through the frontend
   - Verify the account in Supabase if email confirmation is disabled

4. **Run a Test Scan**
   - Create a new project
   - Upload a test file or provide a GitHub repository URL
   - Check that the scan completes successfully

## Troubleshooting

### Frontend Issues

1. **Blank Page**: Check browser console for errors
2. **Supabase Connection Error**: Verify VITE_SUPABASE_URL and VITE_SUPABASE_ANON_KEY
3. **API Connection Error**: Verify VITE_API_URL points to your backend

### Backend Issues

1. **Database Connection**: Check DATABASE_URL or Supabase credentials
2. **Redis Connection**: Verify REDIS_URL is set correctly
3. **CORS Errors**: Ensure CORS_ORIGINS includes your frontend URL

### Common Fixes

1. **Clear Build Cache**: In Render dashboard, go to service → Settings → Clear build cache
2. **Restart Service**: Manual restart from the Render dashboard
3. **Check Logs**: View logs in Render dashboard for detailed error messages

## Security Considerations

1. **Environment Variables**: Never commit sensitive keys to git
2. **CORS**: Only allow your frontend domain in CORS_ORIGINS
3. **API Keys**: Rotate keys regularly
4. **RLS**: Ensure Row Level Security is properly configured in Supabase

## Monitoring

1. Enable Render's built-in metrics
2. Set up alerts for service failures
3. Monitor Supabase usage in the Supabase dashboard
4. Check Redis memory usage

## Support

- Render Documentation: https://render.com/docs
- Supabase Documentation: https://supabase.com/docs
- Project Issues: Create an issue in the GitHub repository