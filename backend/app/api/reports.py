from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import FileResponse, JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_
from typing import List, Optional
from pydantic import BaseModel
from datetime import datetime
import json

from app.utils.database import get_db
from app.models.user import User
from app.models.project import Project
from app.models.scan import Scan
from app.models.report import Report
from app.api.auth import get_current_user
from app.services.report_generator import ReportGenerator

router = APIRouter()

class ReportCreate(BaseModel):
    scan_id: int
    report_type: str = "security"  # security, compliance, executive
    format: str = "json"  # json, pdf, sarif

class ReportResponse(BaseModel):
    id: int
    project_id: int
    scan_id: int
    title: str
    report_type: str
    format: str
    summary: Optional[str]
    launch_ready: bool
    security_score: Optional[int]
    created_at: datetime
    report_file_path: Optional[str]
    
    class Config:
        from_attributes = True

class ComplianceStatus(BaseModel):
    owasp_top_10: dict
    cwe_sans_top_25: dict
    overall_compliance: float

@router.post("/", response_model=ReportResponse)
async def create_report(
    report_data: ReportCreate,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Generate a report for a scan"""
    # Verify scan ownership
    result = await db.execute(
        select(Scan).join(Project).where(
            and_(
                Scan.id == report_data.scan_id,
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
    
    if scan.status != "completed":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Can only generate reports for completed scans"
        )
    
    # Check if report already exists
    existing_report = await db.execute(
        select(Report).where(Report.scan_id == report_data.scan_id)
    )
    if existing_report.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Report already exists for this scan"
        )
    
    # Generate report
    report_generator = ReportGenerator()
    report_content = await report_generator.generate(scan, report_data.report_type)
    
    # Create report record
    report = Report(
        project_id=scan.project_id,
        scan_id=scan.id,
        title=f"{scan.project.name} - {report_data.report_type.title()} Report",
        report_type=report_data.report_type,
        format=report_data.format,
        summary=report_content.get("summary"),
        detailed_findings=report_content.get("findings"),
        statistics=report_content.get("statistics"),
        compliance_status=report_content.get("compliance"),
        launch_ready=report_content.get("launch_ready", False),
        security_score=report_content.get("security_score")
    )
    
    # Generate file if requested
    if report_data.format in ["pdf", "sarif"]:
        file_path = await report_generator.save_to_file(
            report_content, 
            report_data.format,
            f"reports/{current_user.id}/{scan.id}"
        )
        report.report_file_path = file_path
    
    db.add(report)
    await db.commit()
    await db.refresh(report)
    
    return report

@router.get("/", response_model=List[ReportResponse])
async def list_reports(
    project_id: Optional[int] = None,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    skip: int = 0,
    limit: int = 100
):
    """List reports for user's projects"""
    query = select(Report).join(Project).where(Project.owner_id == current_user.id)
    
    if project_id:
        query = query.where(Report.project_id == project_id)
    
    query = query.order_by(Report.created_at.desc()).offset(skip).limit(limit)
    
    result = await db.execute(query)
    reports = result.scalars().all()
    return reports

@router.get("/{report_id}", response_model=ReportResponse)
async def get_report(
    report_id: int,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Get a specific report"""
    result = await db.execute(
        select(Report).join(Project).where(
            and_(
                Report.id == report_id,
                Project.owner_id == current_user.id
            )
        )
    )
    report = result.scalar_one_or_none()
    
    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Report not found"
        )
    
    return report

@router.get("/{report_id}/download")
async def download_report(
    report_id: int,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Download report file"""
    result = await db.execute(
        select(Report).join(Project).where(
            and_(
                Report.id == report_id,
                Project.owner_id == current_user.id
            )
        )
    )
    report = result.scalar_one_or_none()
    
    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Report not found"
        )
    
    if report.format == "json":
        return JSONResponse(
            content={
                "title": report.title,
                "summary": report.summary,
                "findings": report.detailed_findings,
                "statistics": report.statistics,
                "compliance": report.compliance_status,
                "launch_ready": report.launch_ready,
                "security_score": report.security_score
            }
        )
    
    if not report.report_file_path:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Report file not found"
        )
    
    return FileResponse(
        path=report.report_file_path,
        filename=f"{report.title}.{report.format}",
        media_type="application/octet-stream"
    )

@router.get("/{report_id}/compliance", response_model=ComplianceStatus)
async def get_compliance_status(
    report_id: int,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Get compliance status from report"""
    result = await db.execute(
        select(Report).join(Project).where(
            and_(
                Report.id == report_id,
                Project.owner_id == current_user.id
            )
        )
    )
    report = result.scalar_one_or_none()
    
    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Report not found"
        )
    
    if not report.compliance_status:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Compliance data not available for this report"
        )
    
    return ComplianceStatus(
        owasp_top_10=report.compliance_status.get("owasp_top_10", {}),
        cwe_sans_top_25=report.compliance_status.get("cwe_sans_top_25", {}),
        overall_compliance=report.compliance_status.get("overall_compliance", 0.0)
    )

@router.get("/{report_id}/badge")
async def get_launch_ready_badge(
    report_id: int,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Get LaunchReady badge status"""
    result = await db.execute(
        select(Report).join(Project).where(
            and_(
                Report.id == report_id,
                Project.owner_id == current_user.id
            )
        )
    )
    report = result.scalar_one_or_none()
    
    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Report not found"
        )
    
    badge_data = {
        "launch_ready": report.launch_ready,
        "security_score": report.security_score,
        "project_name": report.project.name,
        "scan_date": report.created_at.isoformat(),
        "badge_url": f"{settings.api_url}/badge/{report.project.id}"
    }
    
    if report.launch_ready:
        badge_data["badge_svg"] = generate_badge_svg(
            report.project.name,
            report.security_score
        )
    
    return badge_data

def generate_badge_svg(project_name: str, score: int) -> str:
    """Generate SVG badge for LaunchReady projects"""
    color = "green" if score >= 90 else "yellow" if score >= 70 else "red"
    return f'''<svg xmlns="http://www.w3.org/2000/svg" width="200" height="20">
        <rect width="200" height="20" fill="#555"/>
        <rect x="120" width="80" height="20" fill="{color}"/>
        <text x="10" y="14" fill="#fff" font-family="Arial" font-size="12">LaunchReady</text>
        <text x="130" y="14" fill="#fff" font-family="Arial" font-size="12">Score: {score}</text>
    </svg>'''