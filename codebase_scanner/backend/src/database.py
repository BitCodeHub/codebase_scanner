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
def get_supabase_client() -> Client:
    """
    Get Supabase client instance.
    Uses caching to ensure single instance.
    Raises exception if credentials are not configured.
    """
    url = os.getenv("SUPABASE_URL")
    key = os.getenv("SUPABASE_SERVICE_ROLE_KEY") or os.getenv("SUPABASE_SERVICE_KEY")
    
    if not url:
        error_msg = "SUPABASE_URL environment variable is not set"
        logger.error(error_msg)
        raise ValueError(error_msg)
    
    if not key:
        error_msg = "SUPABASE_SERVICE_ROLE_KEY environment variable is not set"
        logger.error(error_msg)
        raise ValueError(error_msg)
    
    try:
        logger.info(f"Creating Supabase client for URL: {url}")
        client = create_client(url, key)
        # Test the connection
        client.table("projects").select("id").limit(1).execute()
        logger.info("Supabase client created and tested successfully")
        return client
    except Exception as e:
        logger.error(f"Failed to create Supabase client: {e}")
        raise

def get_redis_client():
    """
    Get Redis client for caching.
    """
    import redis
    
    redis_url = os.getenv("REDIS_URL", "redis://localhost:6379")
    return redis.from_url(redis_url, decode_responses=True)