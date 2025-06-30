"""
Simplified FastAPI backend for initial deployment
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
origins = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "https://localhost:5173",
    "https://codebase-scanner-frontend.onrender.com",
    os.getenv("FRONTEND_URL", "")
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "message": "Codebase Scanner API",
        "version": "1.0.0",
        "status": "running",
        "docs": "/docs",
        "configuration": "pending"
    }

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "service": "codebase-scanner-api",
        "timestamp": "2024-12-29",
        "note": "Running in minimal mode - configure environment variables for full functionality"
    }

@app.get("/api/test")
async def test_endpoint():
    """Test endpoint to verify API is working"""
    return {
        "message": "API is working!",
        "supabase_url": os.getenv("SUPABASE_URL", "Not configured"),
        "environment": os.getenv("PYTHON_ENV", "production"),
        "configuration_status": "Please set environment variables in Render dashboard"
    }

@app.get("/api/config/status")
async def config_status():
    """Check configuration status"""
    config = {
        "supabase_url": bool(os.getenv("SUPABASE_URL")),
        "supabase_service_key": bool(os.getenv("SUPABASE_SERVICE_ROLE_KEY")),
        "supabase_anon_key": bool(os.getenv("SUPABASE_ANON_KEY")),
        "anthropic_api_key": bool(os.getenv("ANTHROPIC_API_KEY")),
        "redis_url": bool(os.getenv("REDIS_URL")),
        "frontend_url": os.getenv("FRONTEND_URL", "Not set")
    }
    
    all_configured = all([
        config["supabase_url"],
        config["supabase_service_key"],
        config["supabase_anon_key"],
        config["anthropic_api_key"]
    ])
    
    return {
        "configured": all_configured,
        "services": config,
        "message": "All services configured!" if all_configured else "Please configure required environment variables"
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.main_simple:app", 
        host="0.0.0.0", 
        port=8000, 
        reload=True
    )