# 📋 Step-by-Step Guide: Creating New Docker Backend Service

## Step 1: Create New Docker Service

1. Go to https://dashboard.render.com
2. Click the **"New +"** button (top right)
3. Select **"Web Service"**
4. You'll see your connected GitHub repos - select **codebase_scanner**
5. Click **"Connect"**

### Configuration Page:

**Name**: `codebase-scanner-backend-prod` (or any name you prefer)

**Region**: Select same as your current service (likely Oregon - US West)

**Branch**: `main`

**Runtime**: **Docker** ← This is where you select Docker!

**Dockerfile Path**: `./backend/Dockerfile.production`

**Docker Build Context Directory**: `./backend`

## Step 2: Environment Variables

Scroll down and click **"Advanced"** to expand settings.

Add these environment variables (copy values from your old service):

```bash
# Core Settings
PYTHON_ENV=production
LOG_LEVEL=info
WORKERS=4
DEBUG=false

# Generate a new secret key
SECRET_KEY=<click "Generate" button>

# Supabase (copy from old service)
SUPABASE_URL=https://ylllkgxzrizqlsymkybh.supabase.co
SUPABASE_ANON_KEY=<go to old service Environment tab and copy>
SUPABASE_SERVICE_KEY=<go to old service Environment tab and copy>

# AI Features (critical for Claude analysis)
ANTHROPIC_API_KEY=<your anthropic api key>

# CORS (important!)
CORS_ORIGINS=https://codebase-scanner-frontend.onrender.com
FRONTEND_URL=https://codebase-scanner-frontend.onrender.com

# Optional but recommended
REDIS_URL=<copy if you have it>
```

## Step 3: Select Plan and Create

1. Select your plan:
   - **Free**: Good for testing
   - **Starter/Standard**: Better for production (more memory/CPU)

2. Click **"Create Web Service"**

3. Render will start building your Docker image. This takes 5-10 minutes.

## Step 4: Monitor Deployment

1. You'll be redirected to the new service dashboard
2. Click on **"Logs"** tab
3. Watch for:
   ```
   ==> Building Docker image...
   Installing security tools...
   ✅ Semgrep v1.127.0
   ✅ Bandit v1.8.0
   ✅ Safety v3.5.0
   ✅ Gitleaks v8.27.2
   ✅ TruffleHog v3.89.2
   ... (all 10 tools)
   ```

4. Wait for: `==> Your service is live 🎉`

## Step 5: Test New Service

Your new service URL will be something like:
`https://codebase-scanner-backend-prod.onrender.com`

Test it:

```bash
# 1. Check it's running and showing production
curl https://codebase-scanner-backend-prod.onrender.com/api/test

# Expected response:
{
  "message": "API is working!",
  "environment": "production"  # ← Should say production!
}

# 2. Verify all 10 tools are installed
curl https://codebase-scanner-backend-prod.onrender.com/api/health/tools

# Expected response:
{
  "status": "healthy",
  "total_tools": 10,
  "working_tools": 10,  # ← Should be 10, not 3!
  "percentage": "100%"
}
```

## Step 6: Update Frontend to Use New Backend

1. Go to your **Frontend service** in Render
2. Click **"Environment"** tab
3. Find `VITE_API_URL`
4. Click **"Edit"** 
5. Change from:
   ```
   https://codebase-scanner-backend.onrender.com
   ```
   To your new Docker service URL:
   ```
   https://codebase-scanner-backend-prod.onrender.com
   ```
6. Click **"Save"**
7. Frontend will auto-redeploy (takes 2-3 minutes)

## Step 7: Test Complete System

1. Visit your frontend: https://codebase-scanner-frontend.onrender.com
2. Log in
3. Try scanning a repository
4. Verify it connects to new backend (check browser DevTools Network tab)

## Step 8: Clean Up Old Service

Once everything is working perfectly:

1. Go to your old Python backend service
2. Click **"Settings"** tab
3. Scroll to bottom
4. Click **"Delete Service"**
5. Type the service name to confirm

## 🚨 Important Notes

### What if frontend can't connect?
- Check CORS_ORIGINS in new backend includes your frontend URL
- Make sure VITE_API_URL in frontend has correct new backend URL
- Check browser console for CORS errors

### What if tools still show 3/10?
- You might be hitting the old service
- Clear browser cache
- Verify frontend VITE_API_URL is updated
- Check you used Dockerfile.production, not Dockerfile

### Environment Variables Checklist
Must have for production:
- ✅ PYTHON_ENV=production
- ✅ ANTHROPIC_API_KEY (for AI features)
- ✅ All SUPABASE_* keys
- ✅ CORS_ORIGINS with frontend URL

## 📊 Before/After Comparison

| Feature | Old Python Service | New Docker Service |
|---------|-------------------|-------------------|
| Security Tools | 3/10 (30%) | 10/10 (100%) |
| Runtime | Python | Docker |
| Gitleaks | ❌ | ✅ |
| TruffleHog | ❌ | ✅ |
| detect-secrets | ❌ | ✅ |
| JADX | ❌ | ✅ |
| Production Ready | Partial | Full |

## ✅ Success Checklist

- [ ] New Docker service created and live
- [ ] Shows "environment": "production"
- [ ] Shows 10/10 tools working
- [ ] Frontend updated with new backend URL
- [ ] Can scan repositories from frontend
- [ ] AI analysis working (needs ANTHROPIC_API_KEY)
- [ ] Old service deleted

Once complete, you'll have 100% scanning capability in production!