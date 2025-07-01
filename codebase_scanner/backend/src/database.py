"""
Database connection and client management.
"""
import os
from typing import Optional
from supabase import create_client, Client
from functools import lru_cache
import logging

# Use standard logging if custom logger not available
try:
    from src.utils.logging import get_logger
    logger = get_logger(__name__)
except ImportError:
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)

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
        logger.info(f"Using service key: {'***' + key[-10:] if len(key) > 10 else '***'}")
        
        # Check if we're dealing with the proxy parameter issue
        try:
            # Try creating client normally
            client = create_client(url, key)
        except TypeError as te:
            if "proxy" in str(te):
                logger.warning("Proxy parameter issue detected, trying workaround")
                # This might happen if there's a version mismatch
                # Try to create client with explicit parameters
                from supabase import Client
                import httpx
                client = Client(url, key)
            else:
                raise
        
        # Test the connection with a simple query
        test_result = client.table("projects").select("id").limit(1).execute()
        logger.info(f"Supabase client created and tested successfully")
        return client
    except Exception as e:
        logger.error(f"Failed to create Supabase client: {type(e).__name__}: {str(e)}")
        raise

def get_redis_client():
    """
    Get Redis client for caching.
    """
    import redis
    
    redis_url = os.getenv("REDIS_URL", "redis://localhost:6379")
    return redis.from_url(redis_url, decode_responses=True)