"""
Fixed database connection without proxy parameter.
"""
import os
from typing import Optional
from supabase import create_client, Client
from functools import lru_cache
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@lru_cache()
def get_supabase_client_fixed() -> Client:
    """
    Get Supabase client instance with simplified initialization.
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
        # Create client with only required parameters
        client = create_client(url, key)
        logger.info("Supabase client created successfully")
        return client
    except Exception as e:
        logger.error(f"Failed to create Supabase client: {type(e).__name__}: {str(e)}")
        # If the error is about proxy, try to see if we can work around it
        if "proxy" in str(e).lower():
            logger.info("Attempting to create client without any optional parameters")
            # The issue is likely that the version expects different parameters
            # Let's check what's happening
            import inspect
            sig = inspect.signature(create_client)
            logger.info(f"create_client signature: {sig}")
            logger.info(f"create_client parameters: {list(sig.parameters.keys())}")
        raise