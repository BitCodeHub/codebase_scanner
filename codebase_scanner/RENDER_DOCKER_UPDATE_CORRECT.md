# 🐳 Correct Steps to Change Render to Docker

## Method 1: Create New Docker Service (Recommended)

Since Render doesn't allow changing runtime type after creation, the easiest approach is:

### Step 1: Create New Docker Web Service
1. Go to https://dashboard.render.com
2. Click **"New +"** button
3. Select **"Web Service"**
4. Connect your GitHub repository
5. Select your repo: `codebase_scanner`

### Step 2: Configure as Docker Service
1. **Name**: `codebase-scanner-backend-docker` (or similar)
2. **Region**: Same as your current service (e.g., Oregon)
3. **Branch**: `main`
4. **Runtime**: Select **"Docker"** (not Python)
5. **Dockerfile Path**: `./backend/Dockerfile.production`
6. **Docker Build Context Directory**: `./backend`

### Step 3: Set Environment Variables
Click "Advanced" and add all your environment variables:

```bash
PYTHON_ENV=production
LOG_LEVEL=info
WORKERS=4
SECRET_KEY=<generate new>

# Copy these from your existing service
SUPABASE_URL=https://ylllkgxzrizqlsymkybh.supabase.co
SUPABASE_ANON_KEY=<copy from old service>
SUPABASE_SERVICE_KEY=<copy from old service>
ANTHROPIC_API_KEY=<your anthropic key>

CORS_ORIGINS=https://codebase-scanner-frontend.onrender.com
FRONTEND_URL=https://codebase-scanner-frontend.onrender.com
```

### Step 4: Create Service
1. Select plan (Free or Paid)
2. Click **"Create Web Service"**
3. Wait for deployment (5-10 minutes)

### Step 5: Update Frontend to Point to New Backend
Once the new Docker service is running:

1. Copy the new service URL (e.g., `https://codebase-scanner-backend-docker.onrender.com`)
2. Go to your Frontend service in Render
3. Update the environment variable:
   ```
   VITE_API_URL=https://codebase-scanner-backend-docker.onrender.com
   ```
4. Redeploy frontend

### Step 6: Delete Old Python Service
After verifying everything works:
1. Go to old Python backend service
2. Settings → Delete Service

---

## Method 2: Use render.yaml (Infrastructure as Code)

### Step 1: Update render.yaml
Make sure your `render.yaml` has Docker configuration:

```yaml
services:
  - type: web
    name: codebase-scanner-backend
    runtime: docker
    dockerfilePath: ./backend/Dockerfile.production
    dockerContext: ./backend
    # ... rest of config
```

### Step 2: Create New Blueprint
1. Go to Render Dashboard
2. Click **"New +"** → **"Blueprint"**
3. Connect your GitHub repo
4. Render will read `render.yaml` and create services

### Step 3: Sync Blueprint
This will create new services based on your render.yaml configuration

---

## Method 3: Contact Render Support

If you want to keep the same service URL:

1. Contact Render support
2. Ask them to change your service from Python to Docker runtime
3. They can do this backend change that's not available in UI

---

## Quick Workaround: Update Existing Python Service

If you want to test quickly without creating new service:

### In your existing Python service:
1. Go to **Settings** → **Build & Deploy**
2. Update **Build Command**:
   ```bash
   cd backend && \
   apt-get update && apt-get install -y wget curl && \
   pip install -r requirements.txt && \
   wget https://github.com/gitleaks/gitleaks/releases/download/v8.27.2/gitleaks_8.27.2_linux_x64.tar.gz && \
   tar -xzf gitleaks_8.27.2_linux_x64.tar.gz && \
   mv gitleaks /usr/local/bin/ && \
   wget https://github.com/trufflesecurity/trufflehog/releases/download/v3.89.2/trufflehog_3.89.2_linux_amd64.tar.gz && \
   tar -xzf trufflehog_3.89.2_linux_amd64.tar.gz && \
   mv trufflehog /usr/local/bin/
   ```

3. This installs some tools, but not all (Python runtime has limitations)

---

## 📝 Recommendation

**Create a new Docker service** (Method 1) is the cleanest approach because:
- ✅ All 10 security tools will be installed
- ✅ Better performance with Docker
- ✅ Matches your Dockerfile.production exactly
- ✅ Can test before switching frontend

The key limitation is that Render doesn't allow changing runtime type after service creation, so you need to create a new service or use their Blueprint feature.