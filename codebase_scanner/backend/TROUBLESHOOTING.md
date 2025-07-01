# Backend Troubleshooting Guide

## Current Issue: 502 Bad Gateway Errors

### What This Means
- The Render proxy can't reach your backend application
- Your application might be crashing on startup
- The Docker container might not be running properly

## Troubleshooting Steps

### 1. Check Render Dashboard Logs
Go to https://dashboard.render.com and check the logs for your service.

Look for:
- Build errors
- Runtime errors
- Missing environment variables
- Port binding issues

### 2. Common Issues and Solutions

#### Issue: Environment not showing as "production"
**Solution**: Check if the environment variable is being read correctly:
```python
# In app/config.py
import os
environment = os.getenv("PYTHON_ENV", "development")
```

#### Issue: Application crashing on startup
**Possible causes**:
- Missing dependencies
- Import errors
- Database connection failures
- Missing environment variables

**Check logs for**:
```
ModuleNotFoundError
ImportError
ConnectionError
KeyError
```

#### Issue: Port binding
**Ensure your app starts with**:
```
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

### 3. Manual Testing Commands

Once the service is up, test with:

```bash
# Basic health check
curl https://codebase-scanner-backend-docker.onrender.com/health

# Check environment
curl https://codebase-scanner-backend-docker.onrender.com/api/test | jq .

# Test security tools (this might take 10+ seconds)
curl https://codebase-scanner-backend-docker.onrender.com/api/test/scanner-tools | jq .

# Test AI analysis
curl -X POST https://codebase-scanner-backend-docker.onrender.com/api/test/ai-analysis \
  -H "Content-Type: application/json" | jq .
```

### 4. Docker Debugging

If the Docker build is failing:

1. Check Dockerfile.production syntax
2. Verify all tools are installing correctly
3. Check for permission issues
4. Ensure the app user has necessary permissions

### 5. Environment Variables Checklist

Required variables in Render:
- [ ] PYTHON_ENV=production
- [ ] ANTHROPIC_API_KEY
- [ ] SUPABASE_URL
- [ ] SUPABASE_ANON_KEY
- [ ] SUPABASE_SERVICE_ROLE_KEY
- [ ] SECRET_KEY

### 6. Quick Fixes to Try

1. **Restart the service** in Render dashboard
2. **Clear build cache** and redeploy
3. **Check recent commits** for breaking changes
4. **Verify branch** is correct (should be main/master)

### 7. Testing Individual Components

```python
# Test Supabase connection locally
import os
from supabase import create_client

url = os.getenv("SUPABASE_URL")
key = os.getenv("SUPABASE_ANON_KEY")
supabase = create_client(url, key)

# Test a simple query
result = supabase.table("projects").select("count", count="exact").execute()
print(f"Projects count: {result.count}")
```

### 8. Monitor Script

Use the monitoring script to wait for service recovery:
```bash
python3 monitor_deployment.py
```

### 9. Full Validation

Once the service is up:
```bash
python3 validate_deployment.py
```

### 10. If All Else Fails

1. **Check GitHub Actions** if you have CI/CD
2. **Review recent changes** in git log
3. **Test locally** with Docker:
   ```bash
   docker build -f Dockerfile.production -t codebase-scanner .
   docker run -p 8000:8000 --env-file .env codebase-scanner
   ```
4. **Contact Render support** if infrastructure issue

## Expected Healthy Response

When working correctly, you should see:

```json
// GET /health
{
  "status": "healthy",
  "service": "codebase-scanner-api",
  "timestamp": "2024-12-29"
}

// GET /api/test
{
  "message": "API is working!",
  "supabase_url": "https://ylilkgxzrizqlsymkybh.supabase.co",
  "environment": "production"  // Should be "production"
}

// GET /api/test/scanner-tools
{
  "total_tools": 10,
  "available_tools": 10,  // Should be 10
  "tools": {
    "semgrep": {"available": true, "version": "1.127.0"},
    "bandit": {"available": true, "version": "1.8.0"},
    // ... all 10 tools
  }
}
```

## Next Steps After Resolution

1. Run full validation suite
2. Test file upload scanning
3. Test repository scanning
4. Update frontend to use new backend URL
5. Set up monitoring alerts in Render