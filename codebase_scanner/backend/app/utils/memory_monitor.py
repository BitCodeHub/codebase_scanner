"""Memory monitoring utilities for production deployment."""

import gc
import os
import psutil
import asyncio
from typing import Dict, Any
import structlog

logger = structlog.get_logger(__name__)

class MemoryMonitor:
    """Monitor and manage memory usage in production."""
    
    def __init__(self, max_memory_mb: int = 450):
        """
        Initialize memory monitor.
        
        Args:
            max_memory_mb: Maximum memory threshold in MB (default 450MB for 512MB container)
        """
        self.max_memory_mb = max_memory_mb
        self.process = psutil.Process(os.getpid())
        
    def get_memory_info(self) -> Dict[str, Any]:
        """Get current memory usage information."""
        memory_info = self.process.memory_info()
        memory_percent = self.process.memory_percent()
        
        return {
            "rss_mb": memory_info.rss / 1024 / 1024,
            "vms_mb": memory_info.vms / 1024 / 1024,
            "percent": memory_percent,
            "available_mb": psutil.virtual_memory().available / 1024 / 1024,
            "total_mb": psutil.virtual_memory().total / 1024 / 1024
        }
    
    def check_memory_usage(self) -> bool:
        """
        Check if memory usage is within limits.
        
        Returns:
            True if memory usage is OK, False if over limit
        """
        memory_info = self.get_memory_info()
        current_mb = memory_info["rss_mb"]
        
        if current_mb > self.max_memory_mb:
            logger.warning(
                "Memory usage exceeds threshold",
                current_mb=current_mb,
                max_mb=self.max_memory_mb,
                percent=memory_info["percent"]
            )
            return False
        
        return True
    
    def force_garbage_collection(self):
        """Force garbage collection to free memory."""
        logger.info("Forcing garbage collection")
        collected = gc.collect()
        logger.info(f"Garbage collection freed {collected} objects")
        
    async def monitor_memory_loop(self, interval: int = 60):
        """
        Continuously monitor memory usage.
        
        Args:
            interval: Check interval in seconds
        """
        while True:
            memory_info = self.get_memory_info()
            
            # Log memory status
            logger.info(
                "Memory status",
                rss_mb=round(memory_info["rss_mb"], 2),
                percent=round(memory_info["percent"], 2),
                available_mb=round(memory_info["available_mb"], 2)
            )
            
            # Check if we need to free memory
            if memory_info["rss_mb"] > (self.max_memory_mb * 0.9):  # 90% threshold
                logger.warning("Memory usage high, triggering garbage collection")
                self.force_garbage_collection()
            
            await asyncio.sleep(interval)
    
    @staticmethod
    def optimize_scan_memory(func):
        """
        Decorator to optimize memory usage during scans.
        Forces garbage collection before and after scan.
        """
        async def wrapper(*args, **kwargs):
            # Collect garbage before scan
            gc.collect()
            
            try:
                result = await func(*args, **kwargs)
                return result
            finally:
                # Always collect garbage after scan
                gc.collect()
        
        return wrapper


# Global memory monitor instance
memory_monitor = MemoryMonitor()


def get_memory_status() -> Dict[str, Any]:
    """Get current memory status for health checks."""
    return memory_monitor.get_memory_info()