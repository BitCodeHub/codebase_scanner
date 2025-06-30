"""
Project models for project management.
"""
from datetime import datetime
from typing import Optional, List, Dict
from pydantic import BaseModel, HttpUrl

class ProjectCreate(BaseModel):
    """Model for creating a new project."""
    name: str
    description: Optional[str] = None
    repository_url: Optional[HttpUrl] = None
    language: Optional[str] = None
    framework: Optional[str] = None

class ProjectUpdate(BaseModel):
    """Model for updating a project."""
    name: Optional[str] = None
    description: Optional[str] = None
    repository_url: Optional[HttpUrl] = None
    language: Optional[str] = None
    framework: Optional[str] = None
    active: Optional[bool] = None

class ProjectResponse(BaseModel):
    """Project response model."""
    id: str
    user_id: str
    name: str
    description: Optional[str]
    repository_url: Optional[str]
    language: Optional[str]
    framework: Optional[str]
    active: bool
    created_at: datetime
    updated_at: datetime

class ProjectListResponse(BaseModel):
    """Response for project list with pagination."""
    projects: List[ProjectResponse]
    total: int
    skip: int
    limit: int

class ProjectStats(BaseModel):
    """Project statistics model."""
    project_id: str
    total_scans: int
    completed_scans: int
    total_vulnerabilities: int
    severity_breakdown: Dict[str, int]
    last_scan_date: Optional[datetime]
    security_score: int