"""
Scan API endpoints for security scanning operations.
"""
import os
import uuid
import asyncio
from datetime import datetime
from typing import List, Optional, Dict, Any
from fastapi import APIRouter, HTTPException, Depends, UploadFile, File, Form, BackgroundTasks
from fastapi.responses import JSONResponse
import aiofiles
from supabase import Client

from src.database import get_supabase_client
from src.dependencies import get_current_user
from src.models.user import User
from app.models.scan import (
    ScanCreate, ScanResponse, ScanStatus, ScanType,
    ScanResultResponse, ScanProgressResponse
)
from app.services.scanner_service import ScannerService
from app.services.repository_scanner import RepositoryScanner
from app.utils.file_processor import FileProcessor
from app.utils.result_processor import ResultProcessor

router = APIRouter(prefix="/scans", tags=["scans"])

# Global scanner service instance
scanner_service = None

def get_scanner_service() -> ScannerService:
    """Get or create scanner service instance."""
    global scanner_service
    if scanner_service is None:
        scanner_service = ScannerService(
            supabase_client=get_supabase_client(),
            temp_dir=os.getenv("TEMP_DIR", "/tmp/scans")
        )
    return scanner_service

@router.post("/", response_model=ScanResponse)
async def create_scan(
    background_tasks: BackgroundTasks,
    project_id: str = Form(...),
    scan_type: ScanType = Form(ScanType.FULL),
    file: UploadFile = File(...),
    current_user: User = Depends(get_current_user),
    scanner: ScannerService = Depends(get_scanner_service),
    supabase: Client = Depends(get_supabase_client)
):
    """
    Create a new security scan for uploaded code.
    
    This endpoint accepts a file upload (zip, tar, or individual files) and
    initiates a security scan using multiple scanning tools.
    """
    try:
        # Validate project ownership
        project = supabase.table("projects").select("*").eq("id", project_id).eq("owner_id", current_user.id).single().execute()
        if not project.data:
            raise HTTPException(status_code=404, detail="Project not found")
        
        # Save uploaded file
        upload_dir = os.path.join(scanner.temp_dir, f"upload_{uuid.uuid4()}")
        os.makedirs(upload_dir, exist_ok=True)
        
        file_path = os.path.join(upload_dir, file.filename)
        async with aiofiles.open(file_path, 'wb') as f:
            content = await file.read()
            await f.write(content)
        
        # Create scan record
        scan_data = {
            "id": str(uuid.uuid4()),
            "project_id": project_id,
            "user_id": current_user.id,
            "scan_type": scan_type.value,
            "status": ScanStatus.PENDING.value,
            "created_at": datetime.utcnow().isoformat(),
            "file_name": file.filename,
            "file_size": len(content)
        }
        
        scan_result = supabase.table("scans").insert(scan_data).execute()
        scan_id = scan_result.data[0]["id"]
        
        # Start scan using Celery
        from app.tasks.scan_tasks import process_scan
        task = process_scan.delay(
            scan_id=scan_id,
            file_path=file_path,
            scan_type=scan_type.value,
            user_id=current_user.id
        )
        
        # Store Celery task ID
        supabase.table("scans").update({
            "celery_task_id": task.id
        }).eq("id", scan_id).execute()
        
        return ScanResponse(
            id=scan_id,
            project_id=project_id,
            scan_type=scan_type,
            status=ScanStatus.PENDING,
            created_at=scan_data["created_at"],
            message="Scan initiated successfully"
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to create scan: {str(e)}")

@router.get("/{scan_id}", response_model=ScanResponse)
async def get_scan(
    scan_id: str,
    current_user: User = Depends(get_current_user),
    supabase: Client = Depends(get_supabase_client)
):
    """Get scan details by ID."""
    try:
        scan = supabase.table("scans").select("*, projects(name)").eq("id", scan_id).eq("user_id", current_user.id).single().execute()
        if not scan.data:
            raise HTTPException(status_code=404, detail="Scan not found")
        
        return ScanResponse(**scan.data)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get scan: {str(e)}")

@router.get("/{scan_id}/progress", response_model=ScanProgressResponse)
async def get_scan_progress(
    scan_id: str,
    current_user: User = Depends(get_current_user),
    scanner: ScannerService = Depends(get_scanner_service)
):
    """Get real-time scan progress."""
    try:
        progress = await scanner.get_scan_progress(scan_id)
        if not progress:
            raise HTTPException(status_code=404, detail="Scan not found or no progress available")
        
        return ScanProgressResponse(**progress)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get scan progress: {str(e)}")

@router.get("/{scan_id}/results", response_model=List[ScanResultResponse])
async def get_scan_results(
    scan_id: str,
    severity: Optional[str] = None,
    category: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
    current_user: User = Depends(get_current_user),
    supabase: Client = Depends(get_supabase_client)
):
    """Get scan results with optional filtering."""
    try:
        # Verify scan ownership
        scan = supabase.table("scans").select("id").eq("id", scan_id).eq("user_id", current_user.id).single().execute()
        if not scan.data:
            raise HTTPException(status_code=404, detail="Scan not found")
        
        # Build query
        query = supabase.table("scan_results").select("*").eq("scan_id", scan_id)
        
        if severity:
            query = query.eq("severity", severity)
        if category:
            query = query.eq("category", category)
        
        results = query.range(offset, offset + limit - 1).execute()
        
        return [ScanResultResponse(**result) for result in results.data]
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get scan results: {str(e)}")

@router.post("/{scan_id}/cancel")
async def cancel_scan(
    scan_id: str,
    current_user: User = Depends(get_current_user),
    scanner: ScannerService = Depends(get_scanner_service),
    supabase: Client = Depends(get_supabase_client)
):
    """Cancel a running scan."""
    try:
        # Verify scan ownership
        scan = supabase.table("scans").select("*").eq("id", scan_id).eq("user_id", current_user.id).single().execute()
        if not scan.data:
            raise HTTPException(status_code=404, detail="Scan not found")
        
        if scan.data["status"] not in [ScanStatus.PENDING.value, ScanStatus.RUNNING.value]:
            raise HTTPException(status_code=400, detail="Scan is not in a cancellable state")
        
        # Cancel the scan
        await scanner.cancel_scan(scan_id)
        
        return {"message": "Scan cancelled successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to cancel scan: {str(e)}")

@router.delete("/{scan_id}")
async def delete_scan(
    scan_id: str,
    current_user: User = Depends(get_current_user),
    supabase: Client = Depends(get_supabase_client)
):
    """Delete a scan and its results."""
    try:
        # Verify scan ownership
        scan = supabase.table("scans").select("*").eq("id", scan_id).eq("user_id", current_user.id).single().execute()
        if not scan.data:
            raise HTTPException(status_code=404, detail="Scan not found")
        
        # Delete scan results first
        supabase.table("scan_results").delete().eq("scan_id", scan_id).execute()
        
        # Delete scan
        supabase.table("scans").delete().eq("id", scan_id).execute()
        
        return {"message": "Scan deleted successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to delete scan: {str(e)}")

@router.post("/batch", response_model=List[ScanResponse])
async def create_batch_scan(
    background_tasks: BackgroundTasks,
    project_id: str = Form(...),
    scan_type: ScanType = Form(ScanType.FULL),
    files: List[UploadFile] = File(...),
    current_user: User = Depends(get_current_user),
    scanner: ScannerService = Depends(get_scanner_service),
    supabase: Client = Depends(get_supabase_client)
):
    """Create multiple scans for batch processing."""
    if len(files) > 10:
        raise HTTPException(status_code=400, detail="Maximum 10 files allowed in batch scan")
    
    scans = []
    for file in files:
        scan = await create_scan(
            background_tasks=background_tasks,
            project_id=project_id,
            scan_type=scan_type,
            file=file,
            current_user=current_user,
            scanner=scanner,
            supabase=supabase
        )
        scans.append(scan)
    
    return scans

@router.get("/project/{project_id}", response_model=List[ScanResponse])
async def get_project_scans(
    project_id: str,
    status: Optional[ScanStatus] = None,
    limit: int = 50,
    offset: int = 0,
    current_user: User = Depends(get_current_user),
    supabase: Client = Depends(get_supabase_client)
):
    """Get all scans for a project."""
    try:
        # Verify project ownership
        project = supabase.table("projects").select("id").eq("id", project_id).eq("owner_id", current_user.id).single().execute()
        if not project.data:
            raise HTTPException(status_code=404, detail="Project not found")
        
        query = supabase.table("scans").select("*").eq("project_id", project_id)
        
        if status:
            query = query.eq("status", status.value)
        
        scans = query.order("created_at", desc=True).range(offset, offset + limit - 1).execute()
        
        return [ScanResponse(**scan) for scan in scans.data]
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get project scans: {str(e)}")

@router.get("/stats/summary")
async def get_scan_statistics(
    current_user: User = Depends(get_current_user),
    supabase: Client = Depends(get_supabase_client)
):
    """Get scan statistics for the current user."""
    try:
        # Get scan counts by status
        scans = supabase.table("scans").select("status").eq("user_id", current_user.id).execute()
        
        status_counts = {}
        for scan in scans.data:
            status = scan["status"]
            status_counts[status] = status_counts.get(status, 0) + 1
        
        # Get vulnerability counts by severity
        results = supabase.table("scan_results").select("severity, scan_id").in_(
            "scan_id", [s["id"] for s in scans.data]
        ).execute()
        
        severity_counts = {}
        for result in results.data:
            severity = result["severity"]
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        return {
            "total_scans": len(scans.data),
            "status_breakdown": status_counts,
            "vulnerability_breakdown": severity_counts,
            "last_scan_date": max([s["created_at"] for s in scans.data]) if scans.data else None
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get scan statistics: {str(e)}")

@router.post("/repository", response_model=ScanResponse)
async def scan_repository(
    background_tasks: BackgroundTasks,
    project_id: str = Form(...),
    repository_url: str = Form(...),
    branch: str = Form("main"),
    scan_type: ScanType = Form(ScanType.FULL),
    current_user: User = Depends(get_current_user),
    scanner: ScannerService = Depends(get_scanner_service),
    supabase: Client = Depends(get_supabase_client)
):
    """
    Scan a GitHub repository by cloning it first.
    
    This endpoint clones a repository and runs security scans on it.
    """
    try:
        # Validate project ownership
        project = supabase.table("projects").select("*").eq("id", project_id).eq("owner_id", current_user.id).single().execute()
        if not project.data:
            raise HTTPException(status_code=404, detail="Project not found")
        
        # Initialize repository scanner
        repo_scanner = RepositoryScanner(scanner)
        
        # Start repository scan
        result = await repo_scanner.scan_repository(
            user_id=current_user.id,
            project_id=project_id,
            repo_url=repository_url,
            branch=branch,
            scan_config={
                "scan_type": scan_type.value,
                "enabled_scanners": ["semgrep", "bandit", "safety", "gitleaks"]
            }
        )
        
        return ScanResponse(
            id=result["scan_id"],
            project_id=project_id,
            scan_type=scan_type,
            status=ScanStatus.PENDING,
            created_at=datetime.utcnow().isoformat(),
            repository_url=repository_url,
            branch=branch,
            message="Repository scan initiated successfully"
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to start repository scan: {str(e)}")

@router.get("/repository/{scan_id}/status")
async def get_repository_scan_status(
    scan_id: str,
    current_user: User = Depends(get_current_user),
    supabase: Client = Depends(get_supabase_client)
):
    """Get detailed status of a repository scan."""
    try:
        scan = supabase.table("scans").select("*").eq("id", scan_id).eq("user_id", current_user.id).single().execute()
        if not scan.data:
            raise HTTPException(status_code=404, detail="Scan not found")
        
        return {
            "scan_id": scan_id,
            "status": scan.data["status"],
            "progress": scan.data.get("progress", 0),
            "repository_url": scan.data.get("repository_url"),
            "branch": scan.data.get("branch"),
            "file_count": scan.data.get("file_count"),
            "repository_size": scan.data.get("repository_size"),
            "started_at": scan.data.get("started_at"),
            "completed_at": scan.data.get("completed_at"),
            "error_message": scan.data.get("error_message")
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get repository scan status: {str(e)}")