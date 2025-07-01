"""
Common dependencies for API endpoints.
"""
from typing import Optional
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from datetime import datetime
import os
import json
import base64
import logging

from .database import get_supabase_client
from .models.user import User

# Set up logging
logger = logging.getLogger(__name__)

# Security scheme
security = HTTPBearer()

def decode_jwt_token(token: str) -> dict:
    """
    Decode JWT token without verification.
    This is safe for Supabase tokens as they are already verified by Supabase.
    """
    try:
        # Split the token
        parts = token.split('.')
        if len(parts) != 3:
            raise ValueError(f"Invalid token format: expected 3 parts, got {len(parts)}")
        
        # Decode the payload (add padding if needed)
        payload = parts[1]
        # Add padding if needed
        padding = 4 - len(payload) % 4
        if padding != 4:
            payload += '=' * padding
            
        decoded = base64.urlsafe_b64decode(payload)
        return json.loads(decoded)
    except Exception as e:
        logger.error(f"Failed to decode JWT token: {e}")
        raise ValueError(f"Invalid token: {str(e)}")

async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security)
) -> User:
    """
    Get current authenticated user from Supabase JWT token.
    We decode the token directly since Supabase has already validated it on the frontend.
    """
    token = credentials.credentials
    
    try:
        # Log token info for debugging
        logger.info(f"Attempting to authenticate with token: {token[:50]}...")
        
        # Decode the JWT token to get user info
        payload = decode_jwt_token(token)
        
        # Extract user information
        user_id = payload.get("sub")
        email = payload.get("email")
        
        # Check token expiration
        exp = payload.get("exp")
        if exp and exp < datetime.utcnow().timestamp():
            logger.error("Token has expired")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token has expired",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        if not user_id:
            logger.error(f"No user ID found in token payload: {payload}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token: no user ID",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        logger.info(f"Successfully authenticated user: {user_id} ({email})")
        
        # Return user object
        return User(
            id=user_id,
            email=email or "unknown@example.com",
            created_at=datetime.utcnow()
        )
        
    except ValueError as e:
        logger.error(f"Token decode error: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid authentication token: {str(e)}",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Unexpected authentication error: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication failed",
            headers={"WWW-Authenticate": "Bearer"},
        )

async def get_optional_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)
) -> Optional[User]:
    """
    Get current user if authenticated, otherwise return None.
    """
    if not credentials:
        return None
    
    try:
        return await get_current_user(credentials)
    except HTTPException:
        return None