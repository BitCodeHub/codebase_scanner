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

@app.get("/api/test/list-projects")
async def test_list_projects():
    """Test project listing without authentication"""
    try:
        from src.database import get_supabase_client
        import os
        from supabase import create_client
        
        # Get the supabase client
        url = os.getenv("SUPABASE_URL")
        key = os.getenv("SUPABASE_SERVICE_ROLE_KEY") or os.getenv("SUPABASE_SERVICE_KEY")
        
        if not url or not key:
            return {"error": "Supabase credentials not configured"}
            
        supabase = create_client(url, key)
        
        # Get all projects
        result = supabase.table("projects").select("*").execute()
        
        return {
            "success": True,
            "total_projects": len(result.data),
            "projects": result.data
        }
        
    except Exception as e:
        return {"error": f"Failed to list projects: {str(e)}"}

@app.get("/api/test/scanner-tools")
async def test_scanner_tools():
    """Test if all security scanning tools are available"""
    try:
        import subprocess
        import os
        
        tools_status = {}
        
        # Test Semgrep
        try:
            result = subprocess.run(['semgrep', '--version'], capture_output=True, text=True, timeout=10)
            tools_status['semgrep'] = {
                'available': result.returncode == 0,
                'version': result.stdout.strip() if result.returncode == 0 else None,
                'error': result.stderr if result.returncode != 0 else None
            }
        except Exception as e:
            tools_status['semgrep'] = {'available': False, 'error': str(e)}
        
        # Test Bandit
        try:
            result = subprocess.run(['bandit', '--version'], capture_output=True, text=True, timeout=10)
            tools_status['bandit'] = {
                'available': result.returncode == 0,
                'version': result.stdout.strip() if result.returncode == 0 else None,
                'error': result.stderr if result.returncode != 0 else None
            }
        except Exception as e:
            tools_status['bandit'] = {'available': False, 'error': str(e)}
        
        # Test Safety
        try:
            result = subprocess.run(['safety', '--version'], capture_output=True, text=True, timeout=10)
            tools_status['safety'] = {
                'available': result.returncode == 0,
                'version': result.stdout.strip() if result.returncode == 0 else None,
                'error': result.stderr if result.returncode != 0 else None
            }
        except Exception as e:
            tools_status['safety'] = {'available': False, 'error': str(e)}
        
        # Test Gitleaks
        try:
            result = subprocess.run(['gitleaks', 'version'], capture_output=True, text=True, timeout=10)
            tools_status['gitleaks'] = {
                'available': result.returncode == 0,
                'version': result.stdout.strip() if result.returncode == 0 else None,
                'error': result.stderr if result.returncode != 0 else None
            }
        except Exception as e:
            tools_status['gitleaks'] = {'available': False, 'error': str(e)}
        
        # Check if scanner service can be initialized
        scanner_service_status = {'available': False, 'error': None}
        try:
            # Try to import and initialize scanner service
            from app.services.scanner_service import ScannerService
            from src.database import get_supabase_client
            
            service = ScannerService(
                supabase_client=get_supabase_client(),
                temp_dir=os.getenv("TEMP_DIR", "/tmp/scans")
            )
            scanner_service_status['available'] = True
            scanner_service_status['scanners_count'] = len(service.scanners)
        except Exception as e:
            scanner_service_status['error'] = str(e)
        
        # Calculate overall status
        available_tools = sum(1 for tool in tools_status.values() if tool['available'])
        total_tools = len(tools_status)
        
        return {
            "status": "healthy" if available_tools == total_tools else "partial",
            "available_tools": available_tools,
            "total_tools": total_tools,
            "tools": tools_status,
            "scanner_service": scanner_service_status,
            "recommendations": [
                "Install missing tools using: pip install semgrep bandit safety",
                "Install gitleaks binary: https://github.com/gitleaks/gitleaks#installation"
            ] if available_tools < total_tools else []
        }
        
    except Exception as e:
        return {"error": f"Failed to test scanner tools: {str(e)}"}

@app.post("/api/test/start-scan")
async def test_start_scan(request: dict):
    """Test scan creation without complex dependencies"""
    try:
        import os
        from supabase import create_client
        from datetime import datetime
        
        # Get the supabase client
        url = os.getenv("SUPABASE_URL")
        key = os.getenv("SUPABASE_SERVICE_ROLE_KEY") or os.getenv("SUPABASE_SERVICE_KEY")
        
        if not url or not key:
            return {"error": "Supabase credentials not configured"}
            
        supabase = create_client(url, key)
        
        # Extract required data
        project_id = request.get("project_id")
        user_id = request.get("user_id")
        
        if not project_id or not user_id:
            return {"error": "project_id and user_id are required"}
        
        # Create scan data
        scan_data = {
            "project_id": int(project_id),  # Convert to integer for BIGSERIAL
            "user_id": user_id,
            "scan_type": "security",
            "status": "pending",
            "triggered_by": "manual",
            "scan_config": {
                "scanType": "comprehensive",
                "includeTests": True,
                "includeDependencies": True,
                "severityThreshold": "low"
            },
            "created_at": datetime.utcnow().isoformat()
        }
        
        # Insert scan
        result = supabase.table("scans").insert(scan_data).execute()
        
        if not result.data:
            return {"error": "Failed to create scan - no data returned"}
        
        scan = result.data[0]
        
        return {
            "success": True,
            "scan": scan,
            "scan_id": scan["id"]
        }
        
    except Exception as e:
        return {"error": f"Failed to create scan: {str(e)}"}

@app.post("/api/scans/repository")
async def scan_repository():
    """Simplified repository scanning endpoint"""
    try:
        from fastapi import Form, Depends
        from src.dependencies import get_current_user
        from src.models.user import User
        import os
        from supabase import create_client
        from datetime import datetime
        
        # This is a simplified version that will be replaced with real scanning
        # For now, we'll create a scan record and simulate the process
        
        return {"error": "This endpoint needs form parameters. Use the test endpoint instead."}
        
    except Exception as e:
        return {"error": f"Failed to start repository scan: {str(e)}"}

@app.post("/api/scans/repository-simple")
async def scan_repository_simple(request: dict):
    """Simplified repository scanning without authentication for testing"""
    try:
        import os
        from supabase import create_client
        from datetime import datetime
        import uuid
        
        # Get the supabase client
        url = os.getenv("SUPABASE_URL")
        key = os.getenv("SUPABASE_SERVICE_ROLE_KEY") or os.getenv("SUPABASE_SERVICE_KEY")
        
        if not url or not key:
            return {"error": "Supabase credentials not configured"}
            
        supabase = create_client(url, key)
        
        # Extract required data
        project_id = request.get("project_id")
        repository_url = request.get("repository_url", "https://github.com/OWASP/NodeGoat")
        branch = request.get("branch", "main")
        scan_type = request.get("scan_type", "FULL")
        user_id = request.get("user_id")
        
        if not project_id:
            return {"error": "project_id is required"}
        
        # Create scan data (using 'security' scan_type as 'repository' is not valid enum value)
        scan_data = {
            "project_id": int(project_id),
            "user_id": user_id,
            "scan_type": "security",  # Valid enum values: security, quality, performance, launch_ready, full
            "status": "pending",
            "triggered_by": "manual",
            "branch": branch,
            "scan_config": {
                "scanType": scan_type,
                "repositoryUrl": repository_url,
                "branch": branch,
                "includeTests": True,
                "includeDependencies": True,
                "severityThreshold": "low"
            },
            "created_at": datetime.utcnow().isoformat()
        }
        
        # Insert scan
        result = supabase.table("scans").insert(scan_data).execute()
        
        if not result.data:
            return {"error": "Failed to create scan - no data returned"}
        
        scan = result.data[0]
        
        return {
            "id": str(scan["id"]),
            "project_id": project_id,
            "scan_type": "security",  # Return the actual scan_type used in database
            "status": "pending",
            "created_at": scan["created_at"],
            "repository_url": repository_url,  # Return in response even though not stored in DB
            "branch": branch,
            "message": "Repository scan initiated successfully"
        }
        
    except Exception as e:
        return {"error": f"Failed to start repository scan: {str(e)}"}

@app.post("/api/test/create-project")
async def test_create_project(request: dict):
    """Test project creation without authentication"""
    try:
        from src.database import get_supabase_client
        from datetime import datetime
        
        # Get the supabase client
        try:
            # Direct initialization to avoid proxy parameter issue
            import os
            from supabase import create_client
            url = os.getenv("SUPABASE_URL")
            key = os.getenv("SUPABASE_SERVICE_ROLE_KEY") or os.getenv("SUPABASE_SERVICE_KEY")
            
            if not url or not key:
                return {"error": "Supabase credentials not configured"}
                
            # Create client directly with minimal parameters
            supabase = create_client(url, key)
        except Exception as e:
            return {"error": f"Failed to get Supabase client: {str(e)}"}
        
        # Extract user_id from request
        user_id = request.get("user_id")
        if not user_id:
            return {"error": "user_id is required"}
        
        # Create project data
        project_data = {
            # Don't set id - let database auto-generate it with BIGSERIAL
            "owner_id": user_id,
            "name": request.get("name", f"Test Project {datetime.now()}"),
            "description": request.get("description", "Test project created via API"),
            "github_repo_url": request.get("repository_url"),
            "created_at": datetime.utcnow().isoformat(),
            "updated_at": datetime.utcnow().isoformat()
        }
        
        # Try to insert
        try:
            result = supabase.table("projects").insert(project_data).execute()
            return {
                "success": True,
                "project": result.data[0] if result.data else None,
                "project_id": result.data[0]["id"] if result.data else None
            }
        except Exception as e:
            return {
                "error": f"Failed to insert project: {str(e)}",
                "project_data": project_data
            }
            
    except Exception as e:
        return {"error": f"Unexpected error: {str(e)}"}

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