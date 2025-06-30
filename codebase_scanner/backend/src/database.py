"""
Database connection and client management.
"""
import os
from typing import Optional
from supabase import create_client, Client
from functools import lru_cache
from src.utils.logging import get_logger

logger = get_logger(__name__)

@lru_cache()
def get_supabase_client() -> Optional[Client]:
    """
    Get Supabase client instance.
    Uses caching to ensure single instance.
    Returns None if credentials are not configured.
    """
    url = os.getenv("SUPABASE_URL")
    key = os.getenv("SUPABASE_SERVICE_ROLE_KEY") or os.getenv("SUPABASE_SERVICE_KEY")
    
    if not url or not key:
        logger.warning("Supabase credentials not configured. Some features will be unavailable.")
        return None
    
    try:
        return create_client(url, key)
    except Exception as e:
        logger.error(f"Failed to create Supabase client: {e}")
        return None

def get_redis_client():
    """
    Get Redis client for caching.
    """
    import redis
    
    redis_url = os.getenv("REDIS_URL", "redis://localhost:6379")
    return redis.from_url(redis_url, decode_responses=True)