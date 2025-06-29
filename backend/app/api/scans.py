from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_
from typing import List, Optional
from pydantic import BaseModel
from datetime import datetime
import uuid

from app.utils.database import get_db
from app.models.user import User
from app.models.project import Project
from app.models.scan import Scan, ScanStatus, ScanType, ScanResult, Severity
from app.api.auth import get_current_user
from app.services.scanner import ScannerService
from app.config import settings

router = APIRouter()

class ScanCreate(BaseModel):
    project_id: int
    scan_type: ScanType = ScanType.FULL
    branch: Optional[str] = None
    commit_sha: Optional[str] = None
    scan_config: Optional[dict] = {}

class ScanResultResponse(BaseModel):
    id: int
    rule_id: Optional[str]
    title: str
    description: Optional[str]
    severity: Severity
    category: Optional[str]
    file_path: Optional[str]
    line_number: Optional[int]
    column_number: Optional[int]
    code_snippet: Optional[str]
    vulnerability_type: Optional[str]
    fix_recommendation: Optional[str]
    ai_generated_fix: Optional[str]
    remediation_example: Optional[str]
    
    # Risk Assessment
    cvss_score: Optional[float]
    cvss_vector: Optional[str]
    risk_rating: Optional[str]
    exploitability: Optional[str]
    impact: Optional[str]
    likelihood: Optional[str]
    
    # Compliance & Standards
    owasp_category: Optional[str]
    compliance_mappings: Optional[dict]
    
    # Development Impact
    fix_effort: Optional[str]
    fix_priority: Optional[int]
    
    # Additional Context
    code_context: Optional[dict]
    tags: Optional[List[str]]
    confidence: Optional[str]
    references: Optional[List[str]]
    
    # Affected Dependencies
    affected_packages: Optional[List[str]]
    vulnerable_versions: Optional[dict]
    fixed_versions: Optional[dict]
    dependency_chain: Optional[List[str]]
    
    class Config:
        from_attributes = True

class ScanResponse(BaseModel):
    id: int
    project_id: int
    scan_type: ScanType
    status: ScanStatus
    commit_sha: Optional[str]
    branch: Optional[str]
    triggered_by: Optional[str]
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    created_at: datetime
    total_issues: int
    critical_issues: int
    high_issues: int
    medium_issues: int
    low_issues: int
    error_message: Optional[str]
    results: Optional[List[ScanResultResponse]] = None
    
    class Config:
        from_attributes = True

@router.post("/", response_model=ScanResponse)
async def create_scan(
    scan_data: ScanCreate,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Create and start a new scan"""
    # Verify project ownership
    result = await db.execute(
        select(Project).where(
            Project.id == scan_data.project_id,
            Project.owner_id == current_user.id
        )
    )
    project = result.scalar_one_or_none()
    
    if not project:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Project not found"
        )
    
    # Check for running scans
    running_scans = await db.execute(
        select(Scan).where(
            and_(
                Scan.project_id == scan_data.project_id,
                Scan.status == ScanStatus.RUNNING
            )
        )
    )
    if running_scans.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="A scan is already running for this project"
        )
    
    # Create scan record
    scan = Scan(
        project_id=scan_data.project_id,
        user_id=current_user.id,
        scan_type=scan_data.scan_type,
        status=ScanStatus.PENDING,
        branch=scan_data.branch or project.github_default_branch,
        commit_sha=scan_data.commit_sha,
        triggered_by="manual",
        scan_config=scan_data.scan_config,
        celery_task_id=str(uuid.uuid4())
    )
    
    db.add(scan)
    await db.commit()
    await db.refresh(scan)
    
    # Queue scan job
    scanner_service = ScannerService()
    # Run scan immediately in a separate task to avoid blocking
    import asyncio
    asyncio.create_task(scanner_service.start_scan(scan.id, project, scan))
    
    # Return response without trying to access relationships
    return ScanResponse(
        id=scan.id,
        project_id=scan.project_id,
        scan_type=scan.scan_type,
        status=scan.status,
        commit_sha=scan.commit_sha,
        branch=scan.branch,
        triggered_by=scan.triggered_by,
        started_at=scan.started_at,
        completed_at=scan.completed_at,
        created_at=scan.created_at,
        total_issues=scan.total_issues or 0,
        critical_issues=scan.critical_issues or 0,
        high_issues=scan.high_issues or 0,
        medium_issues=scan.medium_issues or 0,
        low_issues=scan.low_issues or 0,
        error_message=scan.error_message,
        results=None  # Don't include results for new scans
    )

@router.get("/", response_model=List[ScanResponse])
async def list_scans(
    project_id: Optional[int] = None,
    status: Optional[ScanStatus] = None,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    skip: int = 0,
    limit: int = 100
):
    """List scans for user's projects"""
    query = select(Scan).join(Project).where(Project.owner_id == current_user.id)
    
    if project_id:
        query = query.where(Scan.project_id == project_id)
    if status:
        query = query.where(Scan.status == status)
    
    query = query.order_by(Scan.created_at.desc()).offset(skip).limit(limit)
    
    result = await db.execute(query)
    scans = result.scalars().all()
    
    # Convert to response models without accessing relationships
    return [
        ScanResponse(
            id=scan.id,
            project_id=scan.project_id,
            scan_type=scan.scan_type,
            status=scan.status,
            commit_sha=scan.commit_sha,
            branch=scan.branch,
            triggered_by=scan.triggered_by,
            started_at=scan.started_at,
            completed_at=scan.completed_at,
            created_at=scan.created_at,
            total_issues=scan.total_issues or 0,
            critical_issues=scan.critical_issues or 0,
            high_issues=scan.high_issues or 0,
            medium_issues=scan.medium_issues or 0,
            low_issues=scan.low_issues or 0,
            error_message=scan.error_message,
            results=None
        )
        for scan in scans
    ]

@router.get("/{scan_id}", response_model=ScanResponse)
async def get_scan(
    scan_id: int,
    include_results: bool = False,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Get a specific scan"""
    result = await db.execute(
        select(Scan).join(Project).where(
            and_(
                Scan.id == scan_id,
                Project.owner_id == current_user.id
            )
        )
    )
    scan = result.scalar_one_or_none()
    
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found"
        )
    
    # Build response without accessing relationships
    scan_response = ScanResponse(
        id=scan.id,
        project_id=scan.project_id,
        scan_type=scan.scan_type,
        status=scan.status,
        commit_sha=scan.commit_sha,
        branch=scan.branch,
        triggered_by=scan.triggered_by,
        started_at=scan.started_at,
        completed_at=scan.completed_at,
        created_at=scan.created_at,
        total_issues=scan.total_issues or 0,
        critical_issues=scan.critical_issues or 0,
        high_issues=scan.high_issues or 0,
        medium_issues=scan.medium_issues or 0,
        low_issues=scan.low_issues or 0,
        error_message=scan.error_message,
        results=None
    )
    
    if include_results:
        results = await db.execute(
            select(ScanResult).where(ScanResult.scan_id == scan_id)
        )
        scan_response.results = [
            ScanResultResponse(
                id=r.id,
                rule_id=r.rule_id,
                title=r.title,
                description=r.description,
                severity=r.severity,
                category=r.category,
                file_path=r.file_path,
                line_number=r.line_number,
                column_number=r.column_number,
                code_snippet=r.code_snippet,
                vulnerability_type=r.vulnerability_type,
                fix_recommendation=r.fix_recommendation,
                ai_generated_fix=r.ai_generated_fix
            )
            for r in results.scalars().all()
        ]
    
    return scan_response

@router.get("/{scan_id}/results", response_model=List[ScanResultResponse])
async def get_scan_results(
    scan_id: int,
    severity: Optional[Severity] = None,
    category: Optional[str] = None,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    skip: int = 0,
    limit: int = 100
):
    """Get scan results"""
    # Verify scan ownership
    scan_result = await db.execute(
        select(Scan).join(Project).where(
            and_(
                Scan.id == scan_id,
                Project.owner_id == current_user.id
            )
        )
    )
    if not scan_result.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found"
        )
    
    query = select(ScanResult).where(ScanResult.scan_id == scan_id)
    
    if severity:
        query = query.where(ScanResult.severity == severity)
    if category:
        query = query.where(ScanResult.category == category)
    
    query = query.offset(skip).limit(limit)
    
    result = await db.execute(query)
    results = result.scalars().all()
    
    # Log what we're returning
    import logging
    logger = logging.getLogger(__name__)
    logger.info(f"Returning {len(results)} scan results for scan {scan_id}")
    if results:
        logger.info(f"First result rule_id: {results[0].rule_id}")
    
    return results

@router.post("/{scan_id}/cancel")
async def cancel_scan(
    scan_id: int,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Cancel a running scan"""
    result = await db.execute(
        select(Scan).join(Project).where(
            and_(
                Scan.id == scan_id,
                Project.owner_id == current_user.id
            )
        )
    )
    scan = result.scalar_one_or_none()
    
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found"
        )
    
    if scan.status != ScanStatus.RUNNING:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Can only cancel running scans"
        )
    
    # Update scan status
    scan.status = ScanStatus.CANCELLED
    scan.completed_at = datetime.utcnow()
    await db.commit()
    
    # Cancel celery task if applicable
    # celery_app.control.revoke(scan.celery_task_id, terminate=True)
    
    return {"message": "Scan cancelled successfully"}

@router.post("/{scan_id}/results/{result_id}/false-positive")
async def mark_false_positive(
    scan_id: int,
    result_id: int,
    is_false_positive: bool = True,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Mark a scan result as false positive"""
    # Verify ownership
    scan_result = await db.execute(
        select(Scan).join(Project).where(
            and_(
                Scan.id == scan_id,
                Project.owner_id == current_user.id
            )
        )
    )
    if not scan_result.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found"
        )
    
    # Update result
    result = await db.execute(
        select(ScanResult).where(
            and_(
                ScanResult.id == result_id,
                ScanResult.scan_id == scan_id
            )
        )
    )
    scan_result = result.scalar_one_or_none()
    
    if not scan_result:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan result not found"
        )
    
    scan_result.false_positive = is_false_positive
    await db.commit()
    
    return {"message": "Result updated successfully"}