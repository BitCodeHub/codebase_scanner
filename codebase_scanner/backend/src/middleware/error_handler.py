"""
Production error handling middleware.
"""
from fastapi import Request, HTTPException
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException
import traceback
import uuid
from datetime import datetime
from typing import Union

from src.utils.logging import get_logger

logger = get_logger(__name__)

class AppException(Exception):
    """Base application exception."""
    def __init__(self, message: str, status_code: int = 500, details: dict = None):
        self.message = message
        self.status_code = status_code
        self.details = details or {}
        super().__init__(message)

class ScanException(AppException):
    """Scan-related exceptions."""
    pass

class AuthenticationException(AppException):
    """Authentication-related exceptions."""
    def __init__(self, message: str = "Authentication failed", details: dict = None):
        super().__init__(message, status_code=401, details=details)

class AuthorizationException(AppException):
    """Authorization-related exceptions."""
    def __init__(self, message: str = "Access denied", details: dict = None):
        super().__init__(message, status_code=403, details=details)

class ValidationException(AppException):
    """Validation-related exceptions."""
    def __init__(self, message: str, details: dict = None):
        super().__init__(message, status_code=422, details=details)

class ResourceNotFoundException(AppException):
    """Resource not found exceptions."""
    def __init__(self, resource: str, resource_id: str = None):
        message = f"{resource} not found"
        if resource_id:
            message += f": {resource_id}"
        super().__init__(message, status_code=404)

class RateLimitException(AppException):
    """Rate limit exceeded exceptions."""
    def __init__(self, message: str = "Rate limit exceeded", retry_after: int = None):
        details = {}
        if retry_after:
            details["retry_after"] = retry_after
        super().__init__(message, status_code=429, details=details)

async def error_handler_middleware(request: Request, call_next):
    """
    Global error handler middleware.
    Catches all exceptions and returns standardized error responses.
    """
    error_id = str(uuid.uuid4())
    
    try:
        response = await call_next(request)
        return response
        
    except AppException as e:
        # Log application exceptions
        logger.warning(f"Application error: {e.message}", extra={
            "error_id": error_id,
            "status_code": e.status_code,
            "path": request.url.path,
            "method": request.method,
            "details": e.details
        })
        
        return JSONResponse(
            status_code=e.status_code,
            content={
                "error": {
                    "message": e.message,
                    "type": e.__class__.__name__,
                    "error_id": error_id,
                    "timestamp": datetime.utcnow().isoformat(),
                    "details": e.details
                }
            }
        )
        
    except HTTPException as e:
        # Handle FastAPI HTTP exceptions
        logger.warning(f"HTTP exception: {e.detail}", extra={
            "error_id": error_id,
            "status_code": e.status_code,
            "path": request.url.path,
            "method": request.method
        })
        
        return JSONResponse(
            status_code=e.status_code,
            content={
                "error": {
                    "message": e.detail,
                    "type": "HTTPException",
                    "error_id": error_id,
                    "timestamp": datetime.utcnow().isoformat()
                }
            }
        )
        
    except StarletteHTTPException as e:
        # Handle Starlette HTTP exceptions
        logger.warning(f"Starlette HTTP exception: {e.detail}", extra={
            "error_id": error_id,
            "status_code": e.status_code,
            "path": request.url.path,
            "method": request.method
        })
        
        return JSONResponse(
            status_code=e.status_code,
            content={
                "error": {
                    "message": e.detail,
                    "type": "HTTPException",
                    "error_id": error_id,
                    "timestamp": datetime.utcnow().isoformat()
                }
            }
        )
        
    except Exception as e:
        # Log unexpected exceptions
        logger.error(f"Unexpected error: {str(e)}", extra={
            "error_id": error_id,
            "path": request.url.path,
            "method": request.method,
            "traceback": traceback.format_exc()
        }, exc_info=True)
        
        # Don't expose internal errors in production
        message = "An internal server error occurred"
        if request.app.debug:
            message = str(e)
        
        return JSONResponse(
            status_code=500,
            content={
                "error": {
                    "message": message,
                    "type": "InternalServerError",
                    "error_id": error_id,
                    "timestamp": datetime.utcnow().isoformat()
                }
            }
        )

async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """Handle validation errors."""
    errors = []
    for error in exc.errors():
        errors.append({
            "field": ".".join(str(x) for x in error["loc"]),
            "message": error["msg"],
            "type": error["type"]
        })
    
    logger.warning("Validation error", extra={
        "path": request.url.path,
        "method": request.method,
        "errors": errors
    })
    
    return JSONResponse(
        status_code=422,
        content={
            "error": {
                "message": "Validation failed",
                "type": "ValidationError",
                "timestamp": datetime.utcnow().isoformat(),
                "details": {
                    "errors": errors
                }
            }
        }
    )

async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    """Handle HTTP exceptions."""
    error_id = str(uuid.uuid4())
    
    logger.warning(f"HTTP exception: {exc.detail}", extra={
        "error_id": error_id,
        "status_code": exc.status_code,
        "path": request.url.path,
        "method": request.method
    })
    
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": {
                "message": exc.detail,
                "type": "HTTPException",
                "error_id": error_id,
                "timestamp": datetime.utcnow().isoformat()
            }
        }
    )

def setup_exception_handlers(app):
    """Setup exception handlers for the FastAPI app."""
    app.add_exception_handler(RequestValidationError, validation_exception_handler)
    app.add_exception_handler(StarletteHTTPException, http_exception_handler)
    app.add_exception_handler(HTTPException, http_exception_handler)
    app.middleware("http")(error_handler_middleware)