"""
FastAPI backend for Codebase Scanner
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Create FastAPI app
app = FastAPI(
    title="Codebase Scanner API",
    description="Production-grade security scanner backend",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# Configure CORS
cors_origins = os.getenv("CORS_ORIGINS", "").split(",") if os.getenv("CORS_ORIGINS") else []
origins = [
    "http://localhost:5173",  # Frontend development
    "http://127.0.0.1:5173",
    "https://localhost:5173",
] + cors_origins

# Remove empty strings from origins
origins = [origin.strip() for origin in origins if origin.strip()]

print(f"CORS Origins configured: {origins}")

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Setup production middleware
try:
    from src.middleware.error_handler import setup_exception_handlers
    from src.middleware.rate_limit import setup_security_middleware
    
    setup_exception_handlers(app)
    setup_security_middleware(app)
    print("Production middleware loaded successfully")
except ImportError as e:
    print(f"Warning: Production middleware not loaded: {e}")

@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "message": "Codebase Scanner API",
        "version": "1.0.0",
        "status": "running",
        "docs": "/docs"
    }

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "service": "codebase-scanner-api",
        "timestamp": "2024-12-29"
    }

@app.get("/api/test")
async def test_endpoint():
    """Test endpoint to verify API is working"""
    return {
        "message": "API is working!",
        "supabase_url": os.getenv("SUPABASE_URL", "Not configured"),
        "environment": os.getenv("PYTHON_ENV", "development")
    }

@app.get("/api/supabase/test")
async def test_supabase():
    """Test Supabase connection"""
    try:
        from supabase import create_client
        
        url = os.getenv("SUPABASE_URL")
        key = os.getenv("SUPABASE_SERVICE_ROLE_KEY") or os.getenv("SUPABASE_SERVICE_KEY")
        
        if not url or not key:
            return JSONResponse(
                status_code=503,
                content={
                    "status": "not_configured",
                    "message": "Supabase credentials not configured. Please set SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY environment variables.",
                    "supabase_url": "Not set",
                    "supabase_key": "Not set"
                }
            )
        
        # Test connection
        supabase = create_client(url, key)
        
        # Try a simple query
        result = supabase.table("projects").select("id").limit(1).execute()
        
        return {
            "status": "success",
            "message": "Supabase connection working",
            "supabase_url": url,
            "tables_accessible": True
        }
        
    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={
                "status": "error",
                "message": f"Supabase connection failed: {str(e)}",
                "supabase_url": os.getenv("SUPABASE_URL", "Not set")
            }
        )

@app.post("/api/auth/debug")
async def debug_auth(request: dict):
    """Debug authentication token"""
    try:
        import json
        import base64
        
        token = request.get("token", "")
        if not token:
            return {"error": "No token provided"}
        
        # Try to decode the JWT without verification
        parts = token.split('.')
        if len(parts) != 3:
            return {"error": "Invalid token format", "parts": len(parts)}
        
        # Decode header and payload
        header = json.loads(base64.urlsafe_b64decode(parts[0] + '=='))
        payload = json.loads(base64.urlsafe_b64decode(parts[1] + '=='))
        
        # Try to verify with Supabase
        from src.database import get_supabase_client
        
        verification_result = "Not tested"
        user_info = None
        
        try:
            supabase = get_supabase_client()
            user_response = supabase.auth.get_user(token)
            if user_response and user_response.user:
                verification_result = "Valid"
                user_info = {
                    "id": user_response.user.id,
                    "email": user_response.user.email,
                    "created_at": user_response.user.created_at
                }
            else:
                verification_result = "Invalid"
        except Exception as e:
            verification_result = f"Error: {str(e)}"
        
        return {
            "token_header": header,
            "token_payload": payload,
            "supabase_verification": verification_result,
            "user_info": user_info,
            "user_id": payload.get("sub"),
            "email": payload.get("email"),
            "exp": payload.get("exp"),
            "iat": payload.get("iat")
        }
        
    except Exception as e:
        return {"error": str(e), "token_preview": token[:50] + "..." if len(token) > 50 else token}

# Include API routes
try:
    from src.api.ai_analysis import router as ai_router
    app.include_router(ai_router, prefix="/api/ai", tags=["AI Analysis"])
    print("AI analysis routes loaded successfully")
except ImportError as e:
    print(f"AI analysis module import error: {e}")
    # Try loading simplified version without Celery
    try:
        from src.api.ai_analysis_simple import router as ai_router
        app.include_router(ai_router, prefix="/api/ai", tags=["AI Analysis"])
        print("Simplified AI analysis routes loaded successfully")
    except ImportError as e2:
        print(f"Simplified AI analysis module also failed: {e2}")
except Exception as e:
    print(f"Error loading AI analysis module: {e}")

try:
    from src.api.scan import router as scan_router
    app.include_router(scan_router, prefix="/api", tags=["Scans"])
    print("Scan routes loaded successfully")
except ImportError as e:
    print(f"Scan module not found: {e}")

try:
    from src.api.auth import router as auth_router
    app.include_router(auth_router, prefix="/api", tags=["Authentication"])
    print("Auth routes loaded successfully")
except ImportError as e:
    print(f"Auth module not found: {e}")

try:
    from src.api.websocket import router as ws_router
    app.include_router(ws_router, tags=["WebSocket"])
    print("WebSocket routes loaded successfully")
except ImportError as e:
    print(f"WebSocket module not found: {e}")

try:
    from src.api.projects import router as projects_router
    app.include_router(projects_router, prefix="/api", tags=["Projects"])
    print("Project routes loaded successfully")
except ImportError as e:
    print(f"Project module not found: {e}")

try:
    from src.api.export import router as export_router
    app.include_router(export_router, prefix="/api", tags=["Export"])
    print("Export routes loaded successfully")
except ImportError as e:
    print(f"Export module not found: {e}")

try:
    from src.api.compliance import router as compliance_router
    app.include_router(compliance_router, prefix="/api", tags=["Compliance"])
    print("Compliance routes loaded successfully")
except ImportError as e:
    print(f"Compliance module not found: {e}")

# TODO: Add these routes when implemented
# from app.api.auth import router as auth_router
# from app.api.projects import router as projects_router
# app.include_router(auth_router, prefix="/api/auth", tags=["authentication"])
# app.include_router(projects_router, prefix="/api/projects", tags=["projects"])

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.main:app", 
        host="0.0.0.0", 
        port=8000, 
        reload=True
    )