from fastapi import APIRouter
import subprocess
import shutil
import os
from typing import Dict, Any

router = APIRouter()

@router.get("/api/health/tools")
async def check_tools_health() -> Dict[str, Any]:
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
        "percentage": f"{(working_tools/total_tools)*100:.0f}%",
        "tools": tools_status,
        "environment": os.getenv("PYTHON_ENV", "unknown"),
        "render_service": os.getenv("RENDER_SERVICE_NAME", "unknown"),
        "deployment_timestamp": os.getenv("RENDER_DEPLOY_TIMESTAMP", "unknown")
    }

@router.get("/api/health/detailed")
async def detailed_health_check() -> Dict[str, Any]:
    """Comprehensive health check including system resources"""
    import psutil
    from datetime import datetime
    
    # Get system info
    cpu_percent = psutil.cpu_percent(interval=1)
    memory = psutil.virtual_memory()
    disk = psutil.disk_usage('/')
    
    # Check critical services
    services_status = {
        "api": True,
        "database": await check_database_connection(),
        "redis": await check_redis_connection(),
        "file_system": check_file_system()
    }
    
    return {
        "status": "healthy" if all(services_status.values()) else "unhealthy",
        "timestamp": datetime.utcnow().isoformat(),
        "environment": os.getenv("PYTHON_ENV", "unknown"),
        "system": {
            "cpu_usage": f"{cpu_percent}%",
            "memory_usage": f"{memory.percent}%",
            "memory_available": f"{memory.available / (1024**3):.2f} GB",
            "disk_usage": f"{disk.percent}%",
            "disk_free": f"{disk.free / (1024**3):.2f} GB"
        },
        "services": services_status,
        "uptime": get_uptime()
    }

async def check_database_connection() -> bool:
    """Check if database is reachable"""
    try:
        from src.database import get_supabase_client
        client = get_supabase_client()
        # Simple query to test connection
        client.table("projects").select("id").limit(1).execute()
        return True
    except:
        return False

async def check_redis_connection() -> bool:
    """Check if Redis is reachable"""
    try:
        import redis
        r = redis.from_url(os.getenv("REDIS_URL", "redis://localhost:6379/0"))
        r.ping()
        return True
    except:
        return False

def check_file_system() -> bool:
    """Check if critical directories are accessible"""
    try:
        dirs = ["/app/logs", "/app/temp", "/app/uploads"]
        for dir_path in dirs:
            if os.path.exists(dir_path):
                # Test write permission
                test_file = os.path.join(dir_path, ".test_write")
                with open(test_file, 'w') as f:
                    f.write("test")
                os.remove(test_file)
        return True
    except:
        return False

def get_uptime() -> str:
    """Get application uptime"""
    try:
        with open('/proc/uptime', 'r') as f:
            uptime_seconds = float(f.readline().split()[0])
            days = int(uptime_seconds // 86400)
            hours = int((uptime_seconds % 86400) // 3600)
            minutes = int((uptime_seconds % 3600) // 60)
            return f"{days}d {hours}h {minutes}m"
    except:
        return "unknown"