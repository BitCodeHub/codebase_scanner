"""
Celery tasks for background scanning operations.
"""
import os
import asyncio
from datetime import datetime
from typing import Dict, Any
from celery import current_task
from celery.exceptions import SoftTimeLimitExceeded

from app.celery_app import celery_app
from app.services.scanner_service import ScannerService
from app.models.scan import ScanStatus, ScanType
from src.database import get_supabase_client
from src.utils.logging import get_logger, security_logger
from src.api.websocket import send_scan_progress, send_dashboard_update

logger = get_logger(__name__)

@celery_app.task(bind=True, name="app.tasks.scan_tasks.process_scan")
def process_scan(self, scan_id: str, file_path: str, scan_type: str, user_id: str):
    """
    Process a security scan in the background.
    
    Args:
        scan_id: Unique scan identifier
        file_path: Path to the uploaded file
        scan_type: Type of scan (quick, full, custom)
        user_id: User who initiated the scan
    """
    try:
        logger.info(f"Starting scan {scan_id}", extra={
            "scan_id": scan_id,
            "user_id": user_id,
            "scan_type": scan_type
        })
        
        # Update task state
        self.update_state(
            state="PROGRESS",
            meta={
                "current": 0,
                "total": 100,
                "status": "Initializing scan..."
            }
        )
        
        # Initialize scanner service
        scanner = ScannerService(
            supabase_client=get_supabase_client(),
            temp_dir=os.getenv("TEMP_DIR", "/tmp/scans")
        )
        
        # Run scan asynchronously
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        try:
            # Update scan status to running
            supabase = get_supabase_client()
            supabase.table("scans").update({
                "status": ScanStatus.RUNNING.value,
                "started_at": datetime.utcnow().isoformat(),
                "celery_task_id": self.request.id
            }).eq("id", scan_id).execute()
            
            # Send WebSocket notification
            loop.run_until_complete(send_scan_progress(scan_id, {
                "status": "running",
                "percentage": 0,
                "current_scanner": "initializing",
                "message": "Starting security scan..."
            }))
            
            # Process the scan
            result = loop.run_until_complete(
                scanner.scan_codebase(
                    scan_id=scan_id,
                    file_path=file_path,
                    scan_type=ScanType(scan_type)
                )
            )
            
            # Log completion
            security_logger.log_scan_completed(
                scan_id=scan_id,
                duration=result.get("duration", 0),
                total_findings=result.get("total_findings", 0)
            )
            
            # Send completion notification
            loop.run_until_complete(send_scan_progress(scan_id, {
                "status": "completed",
                "percentage": 100,
                "message": "Scan completed successfully",
                "total_findings": result.get("total_findings", 0)
            }))
            
            # Update dashboard
            loop.run_until_complete(send_dashboard_update("scan_completed", {
                "scan_id": scan_id,
                "findings": result.get("total_findings", 0),
                "severity_counts": result.get("severity_counts", {})
            }))
            
            return {
                "scan_id": scan_id,
                "status": "completed",
                "findings": result.get("total_findings", 0),
                "duration": result.get("duration", 0)
            }
            
        finally:
            loop.close()
            
    except SoftTimeLimitExceeded:
        logger.error(f"Scan {scan_id} exceeded time limit")
        _handle_scan_failure(scan_id, "Scan exceeded time limit")
        raise
        
    except Exception as e:
        logger.error(f"Scan {scan_id} failed: {str(e)}", exc_info=True)
        _handle_scan_failure(scan_id, str(e))
        raise
        
    finally:
        # Clean up temporary file
        try:
            if os.path.exists(file_path):
                os.remove(file_path)
        except Exception as e:
            logger.error(f"Failed to clean up file {file_path}: {e}")

@celery_app.task(name="app.tasks.scan_tasks.batch_scan")
def batch_scan(scan_configs: list[Dict[str, Any]]):
    """
    Process multiple scans in batch.
    
    Args:
        scan_configs: List of scan configurations
    """
    results = []
    for config in scan_configs:
        try:
            result = process_scan.delay(
                scan_id=config["scan_id"],
                file_path=config["file_path"],
                scan_type=config["scan_type"],
                user_id=config["user_id"]
            )
            results.append({
                "scan_id": config["scan_id"],
                "task_id": result.id,
                "status": "queued"
            })
        except Exception as e:
            logger.error(f"Failed to queue scan {config['scan_id']}: {e}")
            results.append({
                "scan_id": config["scan_id"],
                "status": "failed",
                "error": str(e)
            })
    
    return results

@celery_app.task(name="app.tasks.scan_tasks.cleanup_old_scans")
def cleanup_old_scans(days: int = 30):
    """
    Clean up old scan data and files.
    
    Args:
        days: Number of days to keep scan data
    """
    try:
        supabase = get_supabase_client()
        cutoff_date = datetime.utcnow() - timedelta(days=days)
        
        # Get old scans
        old_scans = supabase.table("scans")\
            .select("id, file_path")\
            .lt("created_at", cutoff_date.isoformat())\
            .execute()
        
        cleaned = 0
        for scan in old_scans.data:
            try:
                # Delete scan results
                supabase.table("scan_results")\
                    .delete()\
                    .eq("scan_id", scan["id"])\
                    .execute()
                
                # Delete scan record
                supabase.table("scans")\
                    .delete()\
                    .eq("id", scan["id"])\
                    .execute()
                
                cleaned += 1
                
            except Exception as e:
                logger.error(f"Failed to clean scan {scan['id']}: {e}")
        
        logger.info(f"Cleaned up {cleaned} old scans")
        return {"cleaned": cleaned}
        
    except Exception as e:
        logger.error(f"Cleanup task failed: {e}")
        raise

def _handle_scan_failure(scan_id: str, error_message: str):
    """Handle scan failure by updating database and sending notifications."""
    try:
        supabase = get_supabase_client()
        supabase.table("scans").update({
            "status": ScanStatus.FAILED.value,
            "error_message": error_message,
            "completed_at": datetime.utcnow().isoformat()
        }).eq("id", scan_id).execute()
        
        # Send failure notification
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(send_scan_progress(scan_id, {
                "status": "failed",
                "error": error_message,
                "message": "Scan failed"
            }))
        finally:
            loop.close()
            
    except Exception as e:
        logger.error(f"Failed to update scan failure status: {e}")