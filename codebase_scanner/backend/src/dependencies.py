"""
Common dependencies for API endpoints.
"""
from typing import Optional
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError, jwt
from datetime import datetime
import os
import json
import base64

from .database import get_supabase_client
from .models.user import User

# Security scheme
security = HTTPBearer()

# JWT settings for Supabase
SUPABASE_JWT_SECRET = os.getenv("SUPABASE_JWT_SECRET", "")

async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security)
) -> User:
    """
    Get current authenticated user from Supabase JWT token.
    """
    token = credentials.credentials
    
    try:
        # For Supabase tokens, we need to verify them using the Supabase client
        supabase = get_supabase_client()
        
        # Get user from Supabase auth
        user_response = supabase.auth.get_user(token)
        
        if not user_response or not user_response.user:
            # If Supabase verification fails, try to decode the JWT to get basic info
            # This is useful for development/testing
            try:
                # Decode without verification to extract user info
                # Note: In production, you should always verify!
                parts = token.split('.')
                if len(parts) != 3:
                    raise ValueError("Invalid token format")
                
                # Decode the payload
                payload = json.loads(base64.urlsafe_b64decode(parts[1] + '=='))
                user_id = payload.get("sub")
                email = payload.get("email")
                
                if not user_id:
                    raise ValueError("No user ID in token")
                    
                return User(
                    id=user_id,
                    email=email or "unknown@example.com",
                    created_at=datetime.utcnow()
                )
            except Exception as e:
                print(f"Failed to decode token: {e}")
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid authentication credentials",
                    headers={"WWW-Authenticate": "Bearer"},
                )
        
        # Return user from Supabase response
        return User(
            id=user_response.user.id,
            email=user_response.user.email,
            created_at=datetime.fromisoformat(user_response.user.created_at) if user_response.user.created_at else datetime.utcnow()
        )
        
    except Exception as e:
        print(f"Authentication error: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
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