"""Memory-aware health check endpoint."""

from fastapi import APIRouter, HTTPException
from typing import Dict, Any
import os
import psutil

from app.utils.memory_monitor import get_memory_status

router = APIRouter()

@router.get("/health")
async def health_check() -> Dict[str, Any]:
    """
    Enhanced health check with memory monitoring.
    
    Returns health status and memory usage information.
    """
    try:
        memory_info = get_memory_status()
        
        # Check if memory usage is critical (>90%)
        memory_percent = memory_info["percent"]
        memory_status = "healthy"
        
        if memory_percent > 90:
            memory_status = "critical"
        elif memory_percent > 80:
            memory_status = "warning"
        
        return {
            "status": "healthy" if memory_status != "critical" else "degraded",
            "environment": os.getenv("ENVIRONMENT", "unknown"),
            "memory": {
                "status": memory_status,
                "rss_mb": round(memory_info["rss_mb"], 2),
                "percent": round(memory_percent, 2),
                "available_mb": round(memory_info["available_mb"], 2)
            },
            "workers": int(os.getenv("WORKERS", "1")),
            "version": "1.0.0"
        }
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"Health check failed: {str(e)}")

@router.get("/health/detailed")
async def detailed_health_check() -> Dict[str, Any]:
    """
    Detailed health check with system information.
    
    Use sparingly as it may consume additional resources.
    """
    try:
        memory_info = get_memory_status()
        cpu_percent = psutil.cpu_percent(interval=0.1)
        
        # Get process info
        process = psutil.Process(os.getpid())
        process_info = process.as_dict(attrs=['pid', 'name', 'create_time', 'num_threads'])
        
        return {
            "status": "healthy",
            "system": {
                "cpu_percent": cpu_percent,
                "memory": memory_info,
                "process": process_info
            },
            "limits": {
                "max_memory_mb": int(os.getenv("MAX_MEMORY_MB", "450")),
                "max_file_size": int(os.getenv("MAX_FILE_SIZE", "5242880")),
                "max_scan_files": int(os.getenv("MAX_SCAN_FILES", "100"))
            }
        }
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"Detailed health check failed: {str(e)}")