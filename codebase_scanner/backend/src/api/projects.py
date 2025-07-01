"""
Project management API endpoints.
"""
from datetime import datetime
from typing import List, Optional
from fastapi import APIRouter, HTTPException, Depends, Query
from supabase import Client

from src.database import get_supabase_client
from src.dependencies import get_current_user
from src.models.user import User
from src.models.project import (
    ProjectCreate, ProjectUpdate, ProjectResponse, 
    ProjectListResponse, ProjectStats
)
from src.utils.logging import get_logger

router = APIRouter(prefix="/projects", tags=["projects"])
logger = get_logger(__name__)

def db_project_to_response(db_project: dict) -> dict:
    """Map database project fields to API response fields."""
    return {
        "id": str(db_project["id"]),  # Convert bigint to string
        "user_id": db_project["owner_id"],  # Map owner_id to user_id
        "name": db_project["name"],
        "description": db_project.get("description"),
        "repository_url": db_project.get("github_repo_url"),  # Map github_repo_url to repository_url
        "language": db_project.get("language"),
        "framework": db_project.get("framework"),
        "active": db_project.get("is_active", True),  # Map is_active to active
        "created_at": db_project["created_at"],
        "updated_at": db_project["updated_at"]
    }

@router.post("/", response_model=ProjectResponse)
async def create_project(
    project: ProjectCreate,
    current_user: User = Depends(get_current_user),
    supabase: Client = Depends(get_supabase_client)
):
    """Create a new project."""
    logger.info(f"Creating project for user: {current_user.id} ({current_user.email})")
    logger.info(f"Project data received: name={project.name}, description={project.description}, repository_url={project.repository_url}")
    
    try:
        project_data = {
            # Don't set id - let database auto-generate it with BIGSERIAL
            "owner_id": current_user.id,  # Changed from user_id to owner_id to match schema
            "name": project.name,
            "description": project.description,
            "github_repo_url": str(project.repository_url) if project.repository_url else None,  # Map to github_repo_url
            "created_at": datetime.utcnow().isoformat(),
            "updated_at": datetime.utcnow().isoformat()
        }
        
        logger.info(f"Inserting project data: {project_data}")
        
        result = supabase.table("projects").insert(project_data).execute()
        
        if not result.data:
            logger.error(f"No data returned from insert operation")
            raise HTTPException(status_code=500, detail="Project creation failed - no data returned")
        
        logger.info(f"Project created successfully: {result.data[0]['id']}")
        logger.info(f"Supabase response: {result.data[0]}")
        
        response_data = db_project_to_response(result.data[0])
        logger.info(f"Sending response: {response_data}")
        
        return ProjectResponse(**response_data)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to create project: {type(e).__name__}: {str(e)}")
        logger.error(f"Full error details: {repr(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to create project: {str(e)}")

@router.get("/", response_model=ProjectListResponse)
async def list_projects(
    skip: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
    search: Optional[str] = None,
    active_only: bool = True,
    current_user: User = Depends(get_current_user),
    supabase: Client = Depends(get_supabase_client)
):
    """List user's projects with pagination and search."""
    try:
        # Build query (changed from user_id to owner_id to match schema)
        query = supabase.table("projects").select("*").eq("owner_id", current_user.id)
        
        if active_only:
            query = query.eq("is_active", True)  # Changed from active to is_active to match schema
        
        if search:
            query = query.or_(f"name.ilike.%{search}%,description.ilike.%{search}%")
        
        # Get total count
        count_result = query.count()
        total = count_result.count if hasattr(count_result, 'count') else 0
        
        # Get paginated results
        results = query.order("created_at", desc=True)\
            .range(skip, skip + limit - 1)\
            .execute()
        
        projects = [ProjectResponse(**db_project_to_response(project)) for project in results.data]
        
        return ProjectListResponse(
            projects=projects,
            total=total,
            skip=skip,
            limit=limit
        )
        
    except Exception as e:
        logger.error(f"Failed to list projects: {e}")
        raise HTTPException(status_code=500, detail="Failed to list projects")

@router.get("/{project_id}", response_model=ProjectResponse)
async def get_project(
    project_id: str,
    current_user: User = Depends(get_current_user),
    supabase: Client = Depends(get_supabase_client)
):
    """Get project details."""
    try:
        result = supabase.table("projects")\
            .select("*")\
            .eq("id", project_id)\
            .eq("owner_id", current_user.id)\
            .single()\
            .execute()
        
        if not result.data:
            raise HTTPException(status_code=404, detail="Project not found")
        
        return ProjectResponse(**db_project_to_response(result.data))
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get project: {e}")
        raise HTTPException(status_code=500, detail="Failed to get project")

@router.patch("/{project_id}", response_model=ProjectResponse)
async def update_project(
    project_id: str,
    project_update: ProjectUpdate,
    current_user: User = Depends(get_current_user),
    supabase: Client = Depends(get_supabase_client)
):
    """Update project details."""
    try:
        # Check project exists
        existing = supabase.table("projects")\
            .select("id")\
            .eq("id", project_id)\
            .eq("owner_id", current_user.id)\
            .single()\
            .execute()
        
        if not existing.data:
            raise HTTPException(status_code=404, detail="Project not found")
        
        # Update project - map API fields to database fields
        update_data = project_update.dict(exclude_unset=True)
        
        # Map repository_url to github_repo_url if provided
        if "repository_url" in update_data:
            update_data["github_repo_url"] = str(update_data.pop("repository_url")) if update_data["repository_url"] else None
        
        # Map active to is_active if provided
        if "active" in update_data:
            update_data["is_active"] = update_data.pop("active")
            
        update_data["updated_at"] = datetime.utcnow().isoformat()
        
        result = supabase.table("projects")\
            .update(update_data)\
            .eq("id", project_id)\
            .execute()
        
        logger.info(f"Updated project: {project_id}", extra={
            "user_id": current_user.id,
            "updates": list(update_data.keys())
        })
        
        return ProjectResponse(**result.data[0])
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to update project: {e}")
        raise HTTPException(status_code=500, detail="Failed to update project")

@router.delete("/{project_id}")
async def delete_project(
    project_id: str,
    hard_delete: bool = False,
    current_user: User = Depends(get_current_user),
    supabase: Client = Depends(get_supabase_client)
):
    """Delete or deactivate a project."""
    try:
        # Check project exists
        existing = supabase.table("projects")\
            .select("id")\
            .eq("id", project_id)\
            .eq("owner_id", current_user.id)\
            .single()\
            .execute()
        
        if not existing.data:
            raise HTTPException(status_code=404, detail="Project not found")
        
        if hard_delete:
            # Delete all associated data
            # Delete scan results
            scans = supabase.table("scans")\
                .select("id")\
                .eq("project_id", project_id)\
                .execute()
            
            for scan in scans.data:
                supabase.table("scan_results")\
                    .delete()\
                    .eq("scan_id", scan["id"])\
                    .execute()
            
            # Delete scans
            supabase.table("scans")\
                .delete()\
                .eq("project_id", project_id)\
                .execute()
            
            # Delete project
            supabase.table("projects")\
                .delete()\
                .eq("id", project_id)\
                .execute()
            
            logger.info(f"Hard deleted project: {project_id}")
            
        else:
            # Soft delete - just deactivate
            supabase.table("projects")\
                .update({"is_active": False, "updated_at": datetime.utcnow().isoformat()})\
                .eq("id", project_id)\
                .execute()
            
            logger.info(f"Deactivated project: {project_id}")
        
        return {"message": "Project deleted successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to delete project: {e}")
        raise HTTPException(status_code=500, detail="Failed to delete project")

@router.get("/{project_id}/stats", response_model=ProjectStats)
async def get_project_stats(
    project_id: str,
    current_user: User = Depends(get_current_user),
    supabase: Client = Depends(get_supabase_client)
):
    """Get project statistics including scan history and vulnerability trends."""
    try:
        # Verify project ownership
        project = supabase.table("projects")\
            .select("*")\
            .eq("id", project_id)\
            .eq("owner_id", current_user.id)\
            .single()\
            .execute()
        
        if not project.data:
            raise HTTPException(status_code=404, detail="Project not found")
        
        # Get scan statistics
        scans = supabase.table("scans")\
            .select("*")\
            .eq("project_id", project_id)\
            .execute()
        
        total_scans = len(scans.data)
        completed_scans = len([s for s in scans.data if s["status"] == "completed"])
        
        # Get vulnerability statistics
        if scans.data:
            scan_ids = [s["id"] for s in scans.data]
            
            vulnerabilities = supabase.table("scan_results")\
                .select("severity")\
                .in_("scan_id", scan_ids)\
                .execute()
            
            severity_counts = {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0
            }
            
            for vuln in vulnerabilities.data:
                severity = vuln["severity"].lower()
                if severity in severity_counts:
                    severity_counts[severity] += 1
            
            # Get last scan date
            last_scan = max(scans.data, key=lambda x: x["created_at"]) if scans.data else None
            last_scan_date = last_scan["created_at"] if last_scan else None
            
        else:
            severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
            last_scan_date = None
        
        return ProjectStats(
            project_id=project_id,
            total_scans=total_scans,
            completed_scans=completed_scans,
            total_vulnerabilities=sum(severity_counts.values()),
            severity_breakdown=severity_counts,
            last_scan_date=last_scan_date,
            security_score=_calculate_security_score(severity_counts)
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get project stats: {e}")
        raise HTTPException(status_code=500, detail="Failed to get project statistics")

def _calculate_security_score(severity_counts: dict) -> int:
    """Calculate security score based on vulnerability counts."""
    total = sum(severity_counts.values())
    if total == 0:
        return 100
    
    # Weight by severity
    weighted_score = (
        severity_counts["critical"] * 25 +
        severity_counts["high"] * 15 +
        severity_counts["medium"] * 10 +
        severity_counts["low"] * 5
    )
    
    # Normalize to 0-100 scale (inverse)
    max_possible = total * 25  # If all were critical
    score = 100 - min(100, (weighted_score / max_possible) * 100)
    
    return int(score)