# 🐳 Render Docker Deployment Guide

## Step-by-Step Instructions to Update Backend to Docker

### Step 1: Log into Render Dashboard
1. Go to https://dashboard.render.com
2. Click on your backend service: **codebase-scanner-backend**

### Step 2: Change Runtime to Docker

1. In your backend service dashboard, click **"Settings"** tab
2. Scroll down to **"Build & Deploy"** section
3. Find **"Runtime"** setting
4. Click **"Edit"** button next to Runtime
5. Change from **"Python"** to **"Docker"**
6. Click **"Save Changes"**

### Step 3: Configure Docker Settings

After changing to Docker runtime, new fields will appear:

1. **Dockerfile Path**: 
   ```
   ./backend/Dockerfile.production
   ```

2. **Docker Build Context Directory**:
   ```
   ./backend
   ```

3. **Docker Command** (leave empty - uses CMD from Dockerfile)

### Step 4: Update Environment Variables

Click on **"Environment"** tab and add/verify these variables:

```bash
# Core Settings
PYTHON_ENV=production
LOG_LEVEL=info
WORKERS=4
SECRET_KEY=<click "Generate" to create secure key>

# Supabase (you should already have these)
SUPABASE_URL=https://ylllkgxzrizqlsymkybh.supabase.co
SUPABASE_ANON_KEY=<your-anon-key>
SUPABASE_SERVICE_KEY=<your-service-key>

# AI Features
ANTHROPIC_API_KEY=<your-anthropic-api-key>

# CORS
CORS_ORIGINS=https://codebase-scanner-frontend.onrender.com
FRONTEND_URL=https://codebase-scanner-frontend.onrender.com
```

### Step 5: Deploy the Changes

1. After saving all settings, click **"Manual Deploy"** button
2. Select **"Deploy latest commit"**
3. Click **"Deploy"**

### Step 6: Monitor the Deployment

1. Click on **"Logs"** tab to watch the build process
2. You should see Docker building with all 10 security tools:
   ```
   ==> Building Docker image...
   [+] Building...
   Step 1/30 : FROM python:3.11-slim AS base
   Step 2/30 : ENV PYTHONUNBUFFERED=1
   ...
   Installing Semgrep v1.127.0...
   Installing Bandit v1.8.0...
   Installing Gitleaks v8.27.2...
   Installing TruffleHog v3.89.2...
   ```

3. Build typically takes 5-10 minutes for first deployment

### Step 7: Verify Deployment Success

Once deployed, test these endpoints:

```bash
# 1. Check environment (should show "production")
curl https://codebase-scanner-backend.onrender.com/api/test

# Response should include:
{
  "environment": "production",
  "message": "API is working!"
}

# 2. Check all security tools (should show 10/10)
curl https://codebase-scanner-backend.onrender.com/api/health/tools

# Response should show:
{
  "status": "healthy",
  "total_tools": 10,
  "working_tools": 10,
  "percentage": "100%"
}

# 3. Test a simple scan
curl -X POST https://codebase-scanner-backend.onrender.com/api/scans/repository-simple \
  -H "Content-Type: application/json" \
  -d '{"repository_url": "https://github.com/octocat/Hello-World", "branch": "master"}'
```

---

## 🚨 Troubleshooting

### If deployment fails:

1. **Check logs** for specific errors
2. **Common issues**:
   - Missing environment variables
   - Docker build timeout (increase build timeout in settings)
   - Memory limits (upgrade to paid plan if needed)

### If tools are missing:

1. Verify you're using `Dockerfile.production` not `Dockerfile`
2. Check build logs to ensure all tools installed
3. Test with `/api/health/tools` endpoint

### If API returns 500 errors:

1. Check environment variables are set correctly
2. Verify Supabase credentials are valid
3. Ensure ANTHROPIC_API_KEY is set for AI features

---

## 📊 What Happens During Deployment

1. **Render pulls your latest code** from GitHub
2. **Docker build starts** using Dockerfile.production
3. **All 10 security tools** are installed:
   - Semgrep, Bandit, Safety (via pip)
   - Gitleaks, TruffleHog (via wget)
   - Retire.js (via npm)
   - JADX, APKLeaks, QARK (for mobile scanning)
4. **Python dependencies** installed from requirements.txt
5. **Health checks** configured
6. **Service starts** with production settings

---

## ✅ Success Indicators

Your deployment is successful when:

1. ✅ Logs show "Live" status in Render
2. ✅ `/api/test` returns `"environment": "production"`
3. ✅ `/api/health/tools` shows all 10 tools working
4. ✅ Frontend can connect and scan repositories
5. ✅ No errors in Render logs

---

## 🔄 Alternative: Using render.yaml

If you prefer Infrastructure as Code, the `render.yaml` file in your repo is already configured for Docker deployment. You can:

1. Go to Render Dashboard
2. Click "New" > "Blueprint"
3. Connect your GitHub repo
4. Select the branch with render.yaml
5. Render will auto-configure everything

---

## 📞 Need Help?

If you encounter issues:
1. Check the Render logs first
2. Verify all environment variables
3. Ensure Dockerfile.production exists in backend/
4. Contact Render support if infrastructure issues

The Docker deployment ensures all 10 security tools are available in production, giving you 100% scanning capability!