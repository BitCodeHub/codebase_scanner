# 🚀 Production Deployment Fix Guide

## Overview
This guide fixes all production deployment issues for the Codebase Scanner backend on Render.

## Issues Being Fixed

### 1. ✅ Environment showing "development" in production
- **Fix**: Updated main.py to use settings.environment
- **Action**: Set `PYTHON_ENV=production` in Render environment variables

### 2. ✅ Only 3/10 security tools installed
- **Fix**: Created Dockerfile.production with ALL tools
- **Action**: Update Render to use new Dockerfile

### 3. ✅ Tool version mismatches
- **Fix**: Updated all tools to match development versions
- **Action**: Deploy new Docker image

### 4. ✅ Missing endpoints
- **Fix**: All endpoints are in code, just need proper deployment
- **Action**: Redeploy with latest code

## Step-by-Step Deployment Instructions

### Step 1: Update Render Environment Variables

Add these environment variables in Render Dashboard:

```bash
# Core Settings
PYTHON_ENV=production
DEBUG=false
SECRET_KEY=<generate-secure-key>
LOG_LEVEL=info
WORKERS=4

# Supabase Configuration
SUPABASE_URL=https://ylllkgxzrizqlsymkybh.supabase.co
SUPABASE_ANON_KEY=<your-anon-key>
SUPABASE_SERVICE_KEY=<your-service-key>

# AI Features (optional but recommended)
ANTHROPIC_API_KEY=<your-anthropic-key>

# CORS Configuration
CORS_ORIGINS=https://codebase-scanner-frontend.onrender.com
FRONTEND_URL=https://codebase-scanner-frontend.onrender.com
```

### Step 2: Update Render Build Settings

1. Go to Render Dashboard > Your Backend Service > Settings
2. Update the Docker Command to:
   ```
   docker build -f Dockerfile.production -t codebase-scanner-backend .
   ```

### Step 3: Create Tool Health Check Endpoint

Create a new file `/backend/app/api/health.py`:

```python
from fastapi import APIRouter
import subprocess
import shutil

router = APIRouter()

@router.get("/api/health/tools")
async def check_tools_health():
    """Check if all security tools are installed and working"""
    tools_status = {}
    
    # Define tools and their version commands
    tools = {
        "semgrep": ["semgrep", "--version"],
        "bandit": ["bandit", "--version"],
        "safety": ["safety", "--version"],
        "gitleaks": ["gitleaks", "version"],
        "trufflehog": ["trufflehog", "--version"],
        "detect_secrets": ["detect-secrets", "--version"],
        "retire_js": ["retire", "--version"],
        "jadx": ["jadx", "--version"],
        "apkleaks": ["apkleaks", "--version"],
        "qark": ["qark", "--version"]
    }
    
    for tool_name, command in tools.items():
        try:
            # Check if tool exists
            if shutil.which(command[0]):
                # Try to get version
                result = subprocess.run(
                    command, 
                    capture_output=True, 
                    text=True, 
                    timeout=5
                )
                version = result.stdout.strip() or result.stderr.strip()
                tools_status[tool_name] = {
                    "installed": True,
                    "version": version.split('\n')[0] if version else "Unknown",
                    "error": None
                }
            else:
                tools_status[tool_name] = {
                    "installed": False,
                    "version": None,
                    "error": "Tool not found in PATH"
                }
        except Exception as e:
            tools_status[tool_name] = {
                "installed": False,
                "version": None,
                "error": str(e)
            }
    
    # Calculate summary
    total_tools = len(tools)
    working_tools = sum(1 for t in tools_status.values() if t["installed"])
    
    return {
        "status": "healthy" if working_tools == total_tools else "degraded",
        "total_tools": total_tools,
        "working_tools": working_tools,
        "tools": tools_status,
        "environment": os.getenv("PYTHON_ENV", "unknown")
    }
```

### Step 4: Update requirements.txt

Ensure these versions are in `backend/requirements.txt`:

```txt
# Security Tools
semgrep>=1.127.0,<1.128.0
bandit>=1.8.0,<1.9.0
safety>=3.5.0,<3.6.0
detect-secrets>=1.5.0,<1.6.0
apkleaks>=2.6.0,<2.7.0
qark>=4.0.0,<4.1.0
```

### Step 5: Create Deployment Script

Create `backend/scripts/deploy.sh`:

```bash
#!/bin/bash

echo "🚀 Deploying Codebase Scanner Backend..."

# Verify tools installation
echo "📦 Verifying security tools..."
/app/verify_tools.sh

# Run database migrations if needed
echo "🗄️ Checking database..."
# Add migration commands here if needed

# Start the application
echo "🎯 Starting application..."
exec uvicorn app.main:app \
    --host 0.0.0.0 \
    --port ${PORT:-8000} \
    --workers ${WORKERS:-4} \
    --log-level ${LOG_LEVEL:-info}
```

### Step 6: Update render.yaml

Create or update `render.yaml` in the root directory:

```yaml
services:
  - type: web
    name: codebase-scanner-backend
    runtime: docker
    dockerfilePath: ./backend/Dockerfile.production
    dockerContext: ./backend
    envVars:
      - key: PYTHON_ENV
        value: production
      - key: LOG_LEVEL
        value: info
      - key: WORKERS
        value: 4
      - key: SUPABASE_URL
        fromGroup: supabase
      - key: SUPABASE_ANON_KEY
        fromGroup: supabase
      - key: SUPABASE_SERVICE_KEY
        fromGroup: supabase
      - key: ANTHROPIC_API_KEY
        fromGroup: ai
    healthCheckPath: /health
    autoDeploy: false  # Set to true for auto-deploy on push
```

## Verification Steps

After deployment, verify everything is working:

### 1. Check Environment
```bash
curl https://codebase-scanner-backend.onrender.com/api/test
# Should show: "environment": "production"
```

### 2. Check Tools Status
```bash
curl https://codebase-scanner-backend.onrender.com/api/test/scanner-tools
# Should show all 10 tools as available
```

### 3. Check Health Endpoint
```bash
curl https://codebase-scanner-backend.onrender.com/api/health/tools
# Should show detailed status of each tool
```

### 4. Test Security Scan
```bash
curl -X POST https://codebase-scanner-backend.onrender.com/api/scans/repository-simple \
  -H "Content-Type: application/json" \
  -d '{
    "repository_url": "https://github.com/octocat/Hello-World",
    "branch": "master"
  }'
```

## Monitoring

### Add these health checks in Render:

1. **Basic Health**: `/health` - Every 30 seconds
2. **Tools Health**: `/api/health/tools` - Every 5 minutes
3. **API Health**: `/api/test` - Every 2 minutes

### Set up alerts for:
- Service downtime
- Tool failures
- High response times
- Memory/CPU usage

## Rollback Plan

If deployment fails:

1. In Render Dashboard, click "Rollback" to previous version
2. Check logs for specific errors
3. Fix issues in development first
4. Test thoroughly before redeploying

## Expected Results

After successful deployment:

✅ Environment shows "production"  
✅ All 10 security tools available  
✅ Tool versions match development  
✅ All API endpoints accessible  
✅ Comprehensive security scanning works  

## Support

For issues:
1. Check Render logs: Dashboard > Logs
2. Test individual tools: `/api/health/tools`
3. Verify environment variables are set correctly
4. Ensure Docker build completes successfully

---

**Important**: Always test changes in a staging environment before deploying to production!