# Memory Optimization for Render Free Tier (512MB)

## Problem
Your backend is running out of memory because:
- Running 4 uvicorn workers (each uses ~100-150MB)
- Security tools like Semgrep can use 200-300MB during scans
- Total memory usage exceeds 512MB limit

## Immediate Fix - Reduce Workers

Update the last line of your `Dockerfile.production`:

```dockerfile
# Change from 4 workers to 1 worker
CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers 1 --log-level ${LOG_LEVEL:-info}"]
```

## Create Memory-Efficient Startup Script

Create `scripts/start-production.sh`:

```bash
#!/bin/bash
# Memory-optimized startup for Render free tier

# Set memory-efficient Python options
export PYTHONUNBUFFERED=1
export PYTHONDONTWRITEBYTECODE=1
export MALLOC_ARENA_MAX=2
export PYTHONMALLOC=malloc

# Limit memory usage
export MEMORY_LIMIT_MB=450  # Leave some buffer

# Start with only 1 worker to stay under 512MB
exec uvicorn app.main:app \
    --host 0.0.0.0 \
    --port 8000 \
    --workers 1 \
    --loop uvloop \
    --log-level info \
    --limit-max-requests 1000 \
    --timeout-keep-alive 5
```

## Fix Environment Variable Issue

The environment shows "development" because it might not be reading correctly. Update `app/config.py`:

```python
import os
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    # Explicitly read from environment
    environment: str = os.environ.get("PYTHON_ENV", os.getenv("PYTHON_ENV", "development"))
    
    # ... rest of your settings
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"

settings = Settings()
```

## Add Memory Monitoring

Add to `app/main.py` after the health endpoint:

```python
import psutil
import os

@app.get("/health/memory")
async def memory_status():
    """Monitor memory usage"""
    try:
        process = psutil.Process(os.getpid())
        memory_info = process.memory_info()
        vm = psutil.virtual_memory()
        
        return {
            "status": "healthy",
            "process_memory_mb": round(memory_info.rss / 1024 / 1024, 2),
            "process_memory_percent": round(process.memory_percent(), 2),
            "system_memory_percent": vm.percent,
            "available_memory_mb": round(vm.available / 1024 / 1024, 2),
            "worker_count": 1,
            "warning": "Running with reduced workers for memory efficiency"
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}
```

## Memory-Efficient Tool Configuration

Create `app/utils/memory_limits.py`:

```python
# Memory limits for each tool (in MB)
TOOL_MEMORY_LIMITS = {
    "semgrep": 256,
    "bandit": 128,
    "safety": 64,
    "gitleaks": 128,
    "trufflehog": 128,
    "detect-secrets": 64,
    "retire": 64,
    "jadx": 256,
    "apkleaks": 128,
    "qark": 128
}

# Limit concurrent scans
MAX_CONCURRENT_SCANS = 1
MAX_FILE_SIZE_MB = 10
MAX_FILES_PER_SCAN = 100
```

## Deployment Steps

1. **Update Dockerfile.production** - Change workers from 4 to 1
2. **Commit and push**:
   ```bash
   git add Dockerfile.production
   git commit -m "Reduce workers to 1 for memory optimization"
   git push
   ```
3. **Monitor after deployment**:
   ```bash
   curl https://codebase-scanner-backend-docker.onrender.com/health/memory
   ```

## If Still Having Issues

1. **Check logs in Render dashboard** for specific memory errors
2. **Temporarily disable heavy tools** like Semgrep or JADX
3. **Implement scan queuing** instead of concurrent processing
4. **Consider Render's Starter tier** ($7/month) for 512MB more memory

## Expected Memory Usage After Optimization

- Base FastAPI app: ~80-100MB
- Single worker: ~100MB
- Security tools (idle): ~50MB
- During scan: ~200-300MB peak
- **Total: ~400-450MB** (within 512MB limit)

## Testing the Optimization

```bash
# Check if backend is stable
python3 monitor_deployment.py

# Check memory usage
curl https://codebase-scanner-backend-docker.onrender.com/health/memory

# Run validation
python3 validate_deployment.py
```