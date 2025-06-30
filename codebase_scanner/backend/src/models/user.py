"""
User models for authentication and authorization.
"""
from datetime import datetime
from typing import Optional
from pydantic import BaseModel, EmailStr

class User(BaseModel):
    """User model for authenticated users."""
    id: str
    email: EmailStr
    created_at: datetime
    updated_at: Optional[datetime] = None
    
class UserCreate(BaseModel):
    """Model for creating new users."""
    email: EmailStr
    password: str
    
class UserLogin(BaseModel):
    """Model for user login."""
    email: EmailStr
    password: str
    
class UserResponse(BaseModel):
    """User response model (without sensitive data)."""
    id: str
    email: EmailStr
    created_at: datetime