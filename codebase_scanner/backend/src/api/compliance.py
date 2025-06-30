"""
Compliance assessment and reporting API endpoints.
"""
from fastapi import APIRouter, HTTPException, Depends, Query
from typing import List, Optional
import json

from src.dependencies import get_current_user
from src.models.user import User
from src.database import get_supabase_client
from src.utils.compliance import ComplianceMapper, ComplianceFramework
from src.utils.logging import get_logger

router = APIRouter(prefix="/compliance", tags=["compliance"])
logger = get_logger(__name__)

@router.get("/frameworks")
async def list_compliance_frameworks():
    """
    List all supported compliance frameworks.
    """
    frameworks = [
        {
            "id": framework.name,
            "name": framework.value,
            "description": get_framework_description(framework)
        }
        for framework in ComplianceFramework
    ]
    return frameworks

@router.post("/assess/{scan_id}")
async def assess_scan_compliance(
    scan_id: str,
    frameworks: List[str] = Query(..., description="List of compliance frameworks to assess"),
    current_user: User = Depends(get_current_user),
    supabase = Depends(get_supabase_client)
):
    """
    Assess compliance for a specific scan.
    
    Args:
        scan_id: ID of the scan to assess
        frameworks: List of compliance framework IDs
    
    Returns:
        Compliance assessment results
    """
    try:
        # Verify scan ownership
        scan = supabase.table("scans")\
            .select("*")\
            .eq("id", scan_id)\
            .eq("user_id", current_user.id)\
            .single()\
            .execute()
        
        if not scan.data:
            raise HTTPException(status_code=404, detail="Scan not found")
        
        # Get scan results
        results = supabase.table("scan_results")\
            .select("*")\
            .eq("scan_id", scan_id)\
            .execute()
        
        if not results.data:
            return {
                "scan_id": scan_id,
                "compliance_status": "compliant",
                "message": "No vulnerabilities found",
                "frameworks_assessed": frameworks
            }
        
        # Map framework names to valid values
        valid_frameworks = []
        for fw in frameworks:
            try:
                # Try to get the framework by name
                framework = ComplianceFramework[fw]
                valid_frameworks.append(framework.value)
            except KeyError:
                # Try by value
                for cf in ComplianceFramework:
                    if cf.value == fw:
                        valid_frameworks.append(cf.value)
                        break
        
        if not valid_frameworks:
            raise HTTPException(status_code=400, detail="No valid frameworks specified")
        
        # Perform compliance mapping
        mapper = ComplianceMapper()
        compliance_report = mapper.generate_compliance_report(
            vulnerabilities=results.data,
            frameworks=valid_frameworks
        )
        
        # Store compliance assessment
        assessment_data = {
            "scan_id": scan_id,
            "user_id": current_user.id,
            "frameworks": valid_frameworks,
            "report": compliance_report,
            "overall_score": compliance_report["summary"]["overall_compliance_score"]
        }
        
        supabase.table("compliance_assessments")\
            .insert(assessment_data)\
            .execute()
        
        logger.info(f"Compliance assessment completed", extra={
            "scan_id": scan_id,
            "frameworks": valid_frameworks,
            "user_id": current_user.id
        })
        
        return compliance_report
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Compliance assessment failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Compliance assessment failed")

@router.get("/report/{scan_id}")
async def get_compliance_report(
    scan_id: str,
    framework: Optional[str] = None,
    current_user: User = Depends(get_current_user),
    supabase = Depends(get_supabase_client)
):
    """
    Get compliance report for a scan.
    
    Args:
        scan_id: Scan ID
        framework: Optional specific framework to filter
    
    Returns:
        Compliance report
    """
    try:
        # Get the latest compliance assessment
        query = supabase.table("compliance_assessments")\
            .select("*")\
            .eq("scan_id", scan_id)\
            .eq("user_id", current_user.id)\
            .order("created_at", desc=True)\
            .limit(1)
        
        result = query.execute()
        
        if not result.data:
            raise HTTPException(status_code=404, detail="No compliance assessment found")
        
        report = result.data[0]["report"]
        
        # Filter by framework if specified
        if framework:
            if framework not in report.get("framework_details", {}):
                raise HTTPException(status_code=404, detail=f"Framework {framework} not found in assessment")
            
            return {
                "scan_id": scan_id,
                "framework": framework,
                "details": report["framework_details"][framework],
                "overall_score": report["summary"]["overall_compliance_score"]
            }
        
        return report
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to retrieve compliance report: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to retrieve compliance report")

@router.get("/history")
async def get_compliance_history(
    project_id: Optional[str] = None,
    framework: Optional[str] = None,
    limit: int = Query(10, ge=1, le=100),
    current_user: User = Depends(get_current_user),
    supabase = Depends(get_supabase_client)
):
    """
    Get compliance assessment history.
    
    Args:
        project_id: Optional project ID to filter
        framework: Optional framework to filter
        limit: Number of results to return
    
    Returns:
        List of compliance assessments
    """
    try:
        query = supabase.table("compliance_assessments")\
            .select("*, scans(project_id, projects(name))")\
            .eq("user_id", current_user.id)\
            .order("created_at", desc=True)\
            .limit(limit)
        
        # Apply filters
        if project_id:
            # This requires a join through scans table
            query = query.eq("scans.project_id", project_id)
        
        result = query.execute()
        
        # Filter by framework if specified
        assessments = result.data
        if framework:
            assessments = [
                a for a in assessments 
                if framework in a.get("frameworks", [])
            ]
        
        # Format results
        formatted_results = []
        for assessment in assessments:
            formatted_results.append({
                "id": assessment["id"],
                "scan_id": assessment["scan_id"],
                "project": assessment.get("scans", {}).get("projects", {}).get("name"),
                "frameworks": assessment["frameworks"],
                "overall_score": assessment["overall_score"],
                "created_at": assessment["created_at"]
            })
        
        return formatted_results
        
    except Exception as e:
        logger.error(f"Failed to retrieve compliance history: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to retrieve compliance history")

def get_framework_description(framework: ComplianceFramework) -> str:
    """Get description for a compliance framework."""
    descriptions = {
        ComplianceFramework.OWASP_TOP10: "The OWASP Top 10 is a standard awareness document for developers and web application security.",
        ComplianceFramework.PCI_DSS: "Payment Card Industry Data Security Standard for organizations that handle credit cards.",
        ComplianceFramework.HIPAA: "Health Insurance Portability and Accountability Act for protecting sensitive patient data.",
        ComplianceFramework.SOC2: "Service Organization Control 2 for service providers storing customer data in the cloud.",
        ComplianceFramework.ISO27001: "International standard for information security management systems.",
        ComplianceFramework.GDPR: "General Data Protection Regulation for data protection and privacy in the EU.",
        ComplianceFramework.NIST: "NIST Cybersecurity Framework providing standards and best practices.",
        ComplianceFramework.CIS: "Center for Internet Security Controls for cyber defense."
    }
    return descriptions.get(framework, "Security compliance framework")