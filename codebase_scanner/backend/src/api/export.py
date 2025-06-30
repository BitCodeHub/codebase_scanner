"""
Export API endpoints for generating reports.
"""
from fastapi import APIRouter, HTTPException, Depends, Query
from fastapi.responses import StreamingResponse
import io

from src.dependencies import get_current_user
from src.models.user import User
from app.services.export_service import ExportService
from src.database import get_supabase_client
from src.utils.logging import get_logger

router = APIRouter(prefix="/export", tags=["export"])
logger = get_logger(__name__)

@router.get("/scan/{scan_id}")
async def export_scan_report(
    scan_id: str,
    format: str = Query("pdf", regex="^(pdf|json|csv|excel)$"),
    include_ai_analysis: bool = True,
    include_code_snippets: bool = True,
    current_user: User = Depends(get_current_user),
    supabase = Depends(get_supabase_client)
):
    """
    Export scan results in various formats.
    
    Supported formats:
    - pdf: Comprehensive PDF report
    - json: Raw JSON data
    - csv: CSV for spreadsheet analysis
    - excel: Excel workbook with multiple sheets
    """
    try:
        # Verify user owns the scan
        scan = supabase.table("scans")\
            .select("id, projects(name)")\
            .eq("id", scan_id)\
            .eq("user_id", current_user.id)\
            .single()\
            .execute()
        
        if not scan.data:
            raise HTTPException(status_code=404, detail="Scan not found")
        
        # Generate export
        export_service = ExportService()
        export_data = await export_service.export_scan_results(
            scan_id=scan_id,
            format=format,
            include_ai_analysis=include_ai_analysis,
            include_code_snippets=include_code_snippets
        )
        
        # Determine content type and filename
        content_types = {
            "pdf": "application/pdf",
            "json": "application/json",
            "csv": "text/csv",
            "excel": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        }
        
        extensions = {
            "pdf": "pdf",
            "json": "json",
            "csv": "csv",
            "excel": "xlsx"
        }
        
        project_name = scan.data["projects"]["name"].replace(" ", "_")
        filename = f"security_report_{project_name}_{scan_id[:8]}.{extensions[format]}"
        
        logger.info(f"Exported scan report", extra={
            "scan_id": scan_id,
            "format": format,
            "user_id": current_user.id
        })
        
        return StreamingResponse(
            io.BytesIO(export_data),
            media_type=content_types[format],
            headers={
                "Content-Disposition": f"attachment; filename={filename}"
            }
        )
        
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Export failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Export generation failed")

@router.get("/project/{project_id}/summary")
async def export_project_summary(
    project_id: str,
    format: str = Query("pdf", regex="^(pdf|json|excel)$"),
    days: int = Query(30, ge=1, le=365),
    current_user: User = Depends(get_current_user),
    supabase = Depends(get_supabase_client)
):
    """
    Export project summary report with historical data.
    
    Includes:
    - Vulnerability trends over time
    - Scan history
    - Security score progression
    - Top vulnerabilities
    """
    try:
        # Verify project ownership
        project = supabase.table("projects")\
            .select("*")\
            .eq("id", project_id)\
            .eq("user_id", current_user.id)\
            .single()\
            .execute()
        
        if not project.data:
            raise HTTPException(status_code=404, detail="Project not found")
        
        # Get historical data
        from datetime import datetime, timedelta
        cutoff_date = (datetime.utcnow() - timedelta(days=days)).isoformat()
        
        scans = supabase.table("scans")\
            .select("*, scan_results(severity)")\
            .eq("project_id", project_id)\
            .gte("created_at", cutoff_date)\
            .order("created_at")\
            .execute()
        
        # Process data for summary
        summary_data = {
            "project": project.data,
            "period": f"Last {days} days",
            "total_scans": len(scans.data),
            "scan_history": scans.data,
            "generated_at": datetime.utcnow().isoformat()
        }
        
        # Generate appropriate format
        export_service = ExportService()
        
        if format == "json":
            export_data = json.dumps(summary_data, indent=2, default=str).encode('utf-8')
            content_type = "application/json"
            extension = "json"
        else:
            # For PDF and Excel, create custom summary report
            # (Implementation would be similar to scan export)
            raise HTTPException(status_code=501, detail=f"Format {format} not yet implemented for project summary")
        
        filename = f"project_summary_{project.data['name'].replace(' ', '_')}_{days}days.{extension}"
        
        return StreamingResponse(
            io.BytesIO(export_data),
            media_type=content_type,
            headers={
                "Content-Disposition": f"attachment; filename={filename}"
            }
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Project summary export failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Export generation failed")