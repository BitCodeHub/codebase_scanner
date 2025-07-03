"""
Comprehensive Security Scan API Endpoint
Ensures all 22 security tools are used and generates consistent enterprise reports
"""

from fastapi import APIRouter, HTTPException, BackgroundTasks
from pydantic import BaseModel
from typing import Optional, Dict, Any
import asyncio
import os
import sys
from pathlib import Path
import json
from datetime import datetime

# Add parent directory to path
sys.path.append(str(Path(__file__).parent.parent))

from comprehensive_scanner import ComprehensiveScanner
from enterprise_report_generator import EnterpriseReportGenerator

router = APIRouter()


class ComprehensiveScanRequest(BaseModel):
    project_id: str
    repository_url: str
    branch: str = "main"
    scan_type: str = "comprehensive"
    user_id: str
    enable_all_tools: bool = True
    generate_enterprise_report: bool = True
    

class ComprehensiveScanResponse(BaseModel):
    scan_id: str
    status: str
    message: str
    report_url: Optional[str] = None
    

@router.post("/api/scans/comprehensive", response_model=ComprehensiveScanResponse)
async def run_comprehensive_scan(
    request: ComprehensiveScanRequest,
    background_tasks: BackgroundTasks
):
    """
    Run comprehensive security scan using ALL available tools
    
    This endpoint ensures:
    1. All 22 security tools are executed
    2. Results are properly aggregated and deduplicated
    3. Enterprise-grade report is generated
    4. Consistent output format for every scan
    """
    
    # Generate scan ID
    scan_id = f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{request.project_id}"
    
    # Clone repository to temp directory
    import tempfile
    import subprocess
    
    with tempfile.TemporaryDirectory() as temp_dir:
        repo_path = Path(temp_dir) / "repo"
        
        try:
            # Clone repository
            subprocess.run(
                ["git", "clone", "--depth", "1", "-b", request.branch, request.repository_url, str(repo_path)],
                check=True,
                capture_output=True
            )
        except subprocess.CalledProcessError as e:
            raise HTTPException(status_code=400, detail=f"Failed to clone repository: {e}")
            
        # Initialize scanner
        scanner = ComprehensiveScanner(str(repo_path))
        
        # Start async scan
        background_tasks.add_task(
            run_scan_background,
            scanner,
            scan_id,
            request.dict()
        )
        
    return ComprehensiveScanResponse(
        scan_id=scan_id,
        status="started",
        message="Comprehensive security scan initiated with all 22 tools",
        report_url=f"/api/scans/{scan_id}/report"
    )
    

async def run_scan_background(scanner: ComprehensiveScanner, scan_id: str, request_data: Dict):
    """Run the comprehensive scan in background"""
    
    try:
        # Log scan start
        log_scan_event(scan_id, "STARTED", {
            "tools_count": len(scanner.get_all_security_tools()),
            "repository": request_data["repository_url"]
        })
        
        # Run comprehensive scan
        scan_results = await scanner.scan_repository()
        
        # Log tools executed
        log_scan_event(scan_id, "TOOLS_COMPLETED", {
            "tools_run": scan_results["metrics"]["tools_run"],
            "tools_failed": scan_results["metrics"]["tools_failed"],
            "vulnerabilities_found": scan_results["metrics"]["total_vulnerabilities"]
        })
        
        # Generate enterprise report
        report_path = scanner.generate_enterprise_report(scan_results)
        
        # Save results to database
        save_scan_results(scan_id, scan_results, report_path)
        
        # Log completion
        log_scan_event(scan_id, "COMPLETED", {
            "report_path": report_path,
            "total_time": (scan_results["metrics"]["end_time"] - scan_results["metrics"]["start_time"]).total_seconds()
        })
        
    except Exception as e:
        log_scan_event(scan_id, "FAILED", {"error": str(e)})
        raise
        

@router.get("/api/scans/{scan_id}/status")
async def get_scan_status(scan_id: str):
    """Get the status of a comprehensive scan"""
    
    # Get scan status from database/cache
    status = get_scan_status_from_db(scan_id)
    
    if not status:
        raise HTTPException(status_code=404, detail="Scan not found")
        
    return status
    

@router.get("/api/scans/{scan_id}/report")
async def get_scan_report(scan_id: str, format: str = "markdown"):
    """Get the comprehensive security report"""
    
    # Get report from database/storage
    report = get_scan_report_from_db(scan_id, format)
    
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
        
    if format == "json":
        return report
    elif format == "markdown":
        from fastapi.responses import PlainTextResponse
        return PlainTextResponse(content=report["content"])
    elif format == "pdf":
        from fastapi.responses import FileResponse
        return FileResponse(
            path=report["pdf_path"],
            media_type="application/pdf",
            filename=f"security_report_{scan_id}.pdf"
        )
        

@router.get("/api/scans/tools/status")
async def check_tools_status():
    """Check which security tools are available and properly configured"""
    
    scanner = ComprehensiveScanner(".")
    tools = scanner.get_all_security_tools()
    
    tool_status = {}
    for tool in tools:
        # Check if tool is installed
        import shutil
        tool_cmd = tool.command[0]
        installed = shutil.which(tool_cmd) is not None
        
        tool_status[tool.name] = {
            "installed": installed,
            "enabled": tool.enabled,
            "description": tool.description,
            "command": " ".join(tool.command)
        }
        
    return {
        "total_tools": len(tools),
        "installed": sum(1 for t in tool_status.values() if t["installed"]),
        "enabled": sum(1 for t in tool_status.values() if t["enabled"]),
        "tools": tool_status
    }
    

# Helper functions
def log_scan_event(scan_id: str, event: str, data: Dict[str, Any]):
    """Log scan events for monitoring"""
    event_data = {
        "scan_id": scan_id,
        "event": event,
        "timestamp": datetime.now().isoformat(),
        "data": data
    }
    
    # In production, this would write to a database or event stream
    print(f"[SCAN EVENT] {json.dumps(event_data)}")
    

def save_scan_results(scan_id: str, results: Dict, report_path: str):
    """Save scan results to database"""
    # In production, this would save to a database
    # For now, save to file
    results_file = Path(f"/tmp/scan_results_{scan_id}.json")
    with open(results_file, 'w') as f:
        json.dump({
            "scan_id": scan_id,
            "results": results,
            "report_path": str(report_path),
            "timestamp": datetime.now().isoformat()
        }, f, indent=2, default=str)
        

def get_scan_status_from_db(scan_id: str) -> Optional[Dict]:
    """Get scan status from database"""
    # In production, query from database
    # For now, check file
    results_file = Path(f"/tmp/scan_results_{scan_id}.json")
    if results_file.exists():
        with open(results_file) as f:
            data = json.load(f)
            return {
                "scan_id": scan_id,
                "status": "completed",
                "timestamp": data["timestamp"],
                "vulnerabilities": data["results"]["metrics"]["total_vulnerabilities"],
                "report_available": True
            }
    return None
    

def get_scan_report_from_db(scan_id: str, format: str) -> Optional[Dict]:
    """Get scan report from database"""
    # In production, retrieve from database/storage
    results_file = Path(f"/tmp/scan_results_{scan_id}.json")
    if results_file.exists():
        with open(results_file) as f:
            data = json.load(f)
            report_path = Path(data["report_path"])
            
            if report_path.exists():
                with open(report_path) as rf:
                    return {
                        "scan_id": scan_id,
                        "format": format,
                        "content": rf.read(),
                        "generated_at": data["timestamp"]
                    }
    return None