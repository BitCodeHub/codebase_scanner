"""
Rate limiting middleware for API protection.
"""
import time
from typing import Dict, Tuple, Optional
from fastapi import Request, HTTPException
from fastapi.responses import JSONResponse
import redis.asyncio as redis
from datetime import datetime, timedelta
import hashlib
import json

from src.utils.logging import get_logger

logger = get_logger(__name__)

class RateLimiter:
    """
    Token bucket rate limiter with Redis backend.
    """
    
    def __init__(self, redis_client: redis.Redis):
        self.redis = redis_client
        self.default_limits = {
            "default": (100, 3600),  # 100 requests per hour
            "auth": (5, 300),        # 5 auth attempts per 5 minutes
            "scan": (10, 3600),      # 10 scans per hour
            "api": (1000, 3600),     # 1000 API calls per hour
        }
    
    async def check_rate_limit(
        self,
        key: str,
        limit_type: str = "default",
        max_requests: Optional[int] = None,
        window_seconds: Optional[int] = None
    ) -> Tuple[bool, int, int]:
        """
        Check if request is within rate limit.
        
        Returns:
            Tuple of (allowed, remaining_requests, reset_time)
        """
        # Get limit configuration
        if max_requests is None or window_seconds is None:
            max_requests, window_seconds = self.default_limits.get(
                limit_type, 
                self.default_limits["default"]
            )
        
        # Create Redis key
        redis_key = f"rate_limit:{limit_type}:{key}"
        
        # Get current time
        now = int(time.time())
        window_start = now - window_seconds
        
        # Use Redis pipeline for atomic operations
        pipe = self.redis.pipeline()
        
        # Remove old entries
        pipe.zremrangebyscore(redis_key, 0, window_start)
        
        # Count requests in current window
        pipe.zcard(redis_key)
        
        # Execute pipeline
        results = await pipe.execute()
        current_requests = results[1]
        
        # Check if limit exceeded
        if current_requests >= max_requests:
            # Get oldest request time to calculate reset
            oldest = await self.redis.zrange(redis_key, 0, 0, withscores=True)
            if oldest:
                reset_time = int(oldest[0][1]) + window_seconds
            else:
                reset_time = now + window_seconds
                
            return False, 0, reset_time
        
        # Add current request
        await self.redis.zadd(redis_key, {str(now): now})
        await self.redis.expire(redis_key, window_seconds)
        
        remaining = max_requests - current_requests - 1
        reset_time = now + window_seconds
        
        return True, remaining, reset_time

class RateLimitMiddleware:
    """
    FastAPI middleware for rate limiting.
    """
    
    def __init__(self, redis_url: str = "redis://localhost:6379"):
        self.redis_url = redis_url
        self.redis_client = None
        self.enabled = True
        
    async def __call__(self, request: Request, call_next):
        """Process request with rate limiting."""
        # Skip rate limiting for health checks
        if request.url.path in ["/health", "/", "/docs", "/redoc", "/openapi.json"]:
            return await call_next(request)
        
        # Initialize Redis connection if needed
        if self.redis_client is None:
            try:
                self.redis_client = await redis.from_url(self.redis_url)
                self.rate_limiter = RateLimiter(self.redis_client)
            except Exception as e:
                logger.error(f"Failed to connect to Redis: {e}")
                self.enabled = False
        
        # Skip if rate limiting is disabled
        if not self.enabled:
            return await call_next(request)
        
        # Get client identifier
        client_id = self._get_client_id(request)
        
        # Determine rate limit type
        limit_type = self._get_limit_type(request)
        
        # Check rate limit
        try:
            allowed, remaining, reset_time = await self.rate_limiter.check_rate_limit(
                client_id,
                limit_type
            )
            
            if not allowed:
                logger.warning(f"Rate limit exceeded for {client_id}", extra={
                    "client_id": client_id,
                    "limit_type": limit_type,
                    "path": request.url.path
                })
                
                return JSONResponse(
                    status_code=429,
                    content={
                        "error": {
                            "message": "Rate limit exceeded",
                            "type": "RateLimitError",
                            "retry_after": reset_time - int(time.time())
                        }
                    },
                    headers={
                        "X-RateLimit-Limit": str(self.rate_limiter.default_limits[limit_type][0]),
                        "X-RateLimit-Remaining": "0",
                        "X-RateLimit-Reset": str(reset_time),
                        "Retry-After": str(reset_time - int(time.time()))
                    }
                )
            
            # Process request
            response = await call_next(request)
            
            # Add rate limit headers
            response.headers["X-RateLimit-Limit"] = str(
                self.rate_limiter.default_limits[limit_type][0]
            )
            response.headers["X-RateLimit-Remaining"] = str(remaining)
            response.headers["X-RateLimit-Reset"] = str(reset_time)
            
            return response
            
        except Exception as e:
            logger.error(f"Rate limiting error: {e}")
            # Don't block request on rate limit errors
            return await call_next(request)
    
    def _get_client_id(self, request: Request) -> str:
        """Get unique client identifier."""
        # Try to get authenticated user ID
        if hasattr(request.state, "user") and request.state.user:
            return f"user:{request.state.user.id}"
        
        # Try to get API key
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token_hash = hashlib.sha256(auth_header.encode()).hexdigest()[:16]
            return f"token:{token_hash}"
        
        # Fall back to IP address
        client_ip = request.client.host if request.client else "unknown"
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            client_ip = forwarded_for.split(",")[0].strip()
            
        return f"ip:{client_ip}"
    
    def _get_limit_type(self, request: Request) -> str:
        """Determine rate limit type based on endpoint."""
        path = request.url.path
        
        if "/auth/" in path:
            return "auth"
        elif "/scans" in path and request.method == "POST":
            return "scan"
        elif "/api/" in path:
            return "api"
        else:
            return "default"

# Security headers middleware
async def security_headers_middleware(request: Request, call_next):
    """Add security headers to responses."""
    response = await call_next(request)
    
    # Security headers
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Content-Security-Policy"] = "default-src 'self'"
    
    return response

def setup_security_middleware(app):
    """Setup security middleware for the FastAPI app."""
    # Rate limiting
    rate_limiter = RateLimitMiddleware()
    app.middleware("http")(rate_limiter)
    
    # Security headers
    app.middleware("http")(security_headers_middleware)