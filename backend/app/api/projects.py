from fastapi import APIRouter, Depends, HTTPException, status, UploadFile, File
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from typing import List, Optional
from pydantic import BaseModel, HttpUrl
import os
import aiofiles
from datetime import datetime

from app.utils.database import get_db
from app.models.user import User
from app.models.project import Project
from app.api.auth import get_current_user
from app.config import settings

router = APIRouter()

class ProjectCreate(BaseModel):
    name: str
    description: Optional[str] = None
    github_repo_url: Optional[HttpUrl] = None
    scan_config: Optional[dict] = {}
    excluded_paths: Optional[List[str]] = []
    is_public: bool = False

class ProjectUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    scan_config: Optional[dict] = None
    excluded_paths: Optional[List[str]] = None
    is_public: Optional[bool] = None

class ProjectResponse(BaseModel):
    id: int
    name: str
    description: Optional[str]
    owner_id: int
    github_repo_url: Optional[str]
    uploaded_file_path: Optional[str]
    scan_config: dict
    excluded_paths: List[str]
    is_public: bool
    created_at: datetime
    updated_at: Optional[datetime]
    last_scan_at: Optional[datetime]
    
    class Config:
        from_attributes = True

@router.post("/", response_model=ProjectResponse)
async def create_project(
    project_data: ProjectCreate,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Create a new project"""
    project = Project(
        name=project_data.name,
        description=project_data.description,
        owner_id=current_user.id,
        github_repo_url=str(project_data.github_repo_url) if project_data.github_repo_url else None,
        scan_config=project_data.scan_config,
        excluded_paths=project_data.excluded_paths,
        is_public=project_data.is_public
    )
    
    db.add(project)
    await db.commit()
    await db.refresh(project)
    
    return project

@router.get("/", response_model=List[ProjectResponse])
async def list_projects(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    skip: int = 0,
    limit: int = 100
):
    """List user's projects"""
    result = await db.execute(
        select(Project)
        .where(Project.owner_id == current_user.id)
        .offset(skip)
        .limit(limit)
    )
    projects = result.scalars().all()
    return projects

@router.get("/{project_id}", response_model=ProjectResponse)
async def get_project(
    project_id: int,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Get a specific project"""
    result = await db.execute(
        select(Project).where(
            Project.id == project_id,
            Project.owner_id == current_user.id
        )
    )
    project = result.scalar_one_or_none()
    
    if not project:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Project not found"
        )
    
    return project

@router.patch("/{project_id}", response_model=ProjectResponse)
async def update_project(
    project_id: int,
    project_update: ProjectUpdate,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Update a project"""
    result = await db.execute(
        select(Project).where(
            Project.id == project_id,
            Project.owner_id == current_user.id
        )
    )
    project = result.scalar_one_or_none()
    
    if not project:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Project not found"
        )
    
    # Update fields
    update_data = project_update.dict(exclude_unset=True)
    for field, value in update_data.items():
        setattr(project, field, value)
    
    await db.commit()
    await db.refresh(project)
    
    return project

@router.delete("/{project_id}")
async def delete_project(
    project_id: int,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Delete a project"""
    result = await db.execute(
        select(Project).where(
            Project.id == project_id,
            Project.owner_id == current_user.id
        )
    )
    project = result.scalar_one_or_none()
    
    if not project:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Project not found"
        )
    
    await db.delete(project)
    await db.commit()
    
    return {"message": "Project deleted successfully"}

@router.post("/{project_id}/upload")
async def upload_code(
    project_id: int,
    file: UploadFile = File(...),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Upload code for a project"""
    # Verify project ownership
    result = await db.execute(
        select(Project).where(
            Project.id == project_id,
            Project.owner_id == current_user.id
        )
    )
    project = result.scalar_one_or_none()
    
    if not project:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Project not found"
        )
    
    # Check file size
    if file.size > settings.max_file_size_mb * 1024 * 1024:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"File size exceeds {settings.max_file_size_mb}MB limit"
        )
    
    # Save file
    upload_dir = f"uploads/{current_user.id}/{project_id}"
    os.makedirs(upload_dir, exist_ok=True)
    file_path = f"{upload_dir}/{file.filename}"
    
    async with aiofiles.open(file_path, 'wb') as f:
        content = await file.read()
        await f.write(content)
    
    # Update project
    project.uploaded_file_path = file_path
    await db.commit()
    
    return {"message": "File uploaded successfully", "file_path": file_path}