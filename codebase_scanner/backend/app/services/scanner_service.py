"""
Main scanning service that orchestrates security scanning operations.
"""

import asyncio
import logging
import os
import tempfile
import uuid
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from enum import Enum

from app.database import db
from app.services.scanners.semgrep_scanner import SemgrepScanner
from app.services.scanners.bandit_scanner import BanditScanner
from app.services.scanners.safety_scanner import SafetyScanner
from app.services.scanners.gitleaks_scanner import GitleaksScanner
from app.utils.file_processor import FileProcessor
from app.utils.result_processor import ResultProcessor

logger = logging.getLogger(__name__)


class ScanStatus(str, Enum):
    """Scan status enumeration"""
    PENDING = "pending"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ScannerType(str, Enum):
    """Scanner type enumeration"""
    SEMGREP = "semgrep"
    BANDIT = "bandit"
    SAFETY = "safety"
    GITLEAKS = "gitleaks"


class ScannerService:
    """
    Main service for orchestrating security scans.
    
    This service manages the entire scanning lifecycle including:
    - File upload and processing
    - Scanner orchestration
    - Result processing and storage
    - Progress tracking and status updates
    """
    
    def __init__(self):
        """Initialize the scanner service with all available scanners."""
        self.scanners = {
            ScannerType.SEMGREP: SemgrepScanner(),
            ScannerType.BANDIT: BanditScanner(),
            ScannerType.SAFETY: SafetyScanner(),
            ScannerType.GITLEAKS: GitleaksScanner(),
        }
        self.file_processor = FileProcessor()
        self.result_processor = ResultProcessor()
        self._active_scans: Dict[str, asyncio.Task] = {}
    
    async def start_scan(
        self,
        user_id: str,
        project_id: int,
        file_data: bytes,
        filename: str,
        scan_config: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Start a new security scan.
        
        Args:
            user_id: ID of the user initiating the scan
            project_id: ID of the project being scanned
            file_data: Raw file data to scan
            filename: Original filename
            scan_config: Optional scan configuration
            
        Returns:
            Dict containing scan details including scan_id
        """
        scan_id = str(uuid.uuid4())
        
        # Create scan record in database
        scan_data = {
            "id": scan_id,
            "user_id": user_id,
            "project_id": project_id,
            "status": ScanStatus.PENDING,
            "filename": filename,
            "file_size": len(file_data),
            "config": scan_config or {},
            "started_at": datetime.utcnow().isoformat(),
            "progress": 0,
            "scanners": self._get_enabled_scanners(scan_config)
        }
        
        try:
            scan_record = await db.create_scan(scan_data)
            
            # Start async scan task
            scan_task = asyncio.create_task(
                self._execute_scan(scan_id, file_data, filename, scan_config)
            )
            self._active_scans[scan_id] = scan_task
            
            return {
                "scan_id": scan_id,
                "status": ScanStatus.PENDING,
                "message": "Scan initiated successfully"
            }
            
        except Exception as e:
            logger.error(f"Failed to start scan: {e}")
            raise
    
    async def get_scan_status(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """
        Get the current status of a scan.
        
        Args:
            scan_id: ID of the scan
            
        Returns:
            Dict containing scan status and details
        """
        scan = await db.get_scan(scan_id)
        if not scan:
            return None
            
        # Add real-time status if scan is active
        if scan_id in self._active_scans:
            task = self._active_scans[scan_id]
            if not task.done():
                scan["is_active"] = True
            else:
                # Clean up completed tasks
                del self._active_scans[scan_id]
                
        return scan
    
    async def cancel_scan(self, scan_id: str, user_id: str) -> bool:
        """
        Cancel an active scan.
        
        Args:
            scan_id: ID of the scan to cancel
            user_id: ID of the user requesting cancellation
            
        Returns:
            True if scan was cancelled, False otherwise
        """
        scan = await db.get_scan(scan_id)
        if not scan or scan["user_id"] != user_id:
            return False
            
        if scan_id in self._active_scans:
            task = self._active_scans[scan_id]
            if not task.done():
                task.cancel()
                await db.update_scan(scan_id, {
                    "status": ScanStatus.CANCELLED,
                    "completed_at": datetime.utcnow().isoformat()
                })
                return True
                
        return False
    
    async def _execute_scan(
        self,
        scan_id: str,
        file_data: bytes,
        filename: str,
        scan_config: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Execute the actual scanning process.
        
        This method handles the entire scanning lifecycle:
        1. Extract and prepare files
        2. Run enabled scanners
        3. Process and store results
        4. Clean up temporary files
        """
        temp_dir = None
        
        try:
            # Update scan status to processing
            await db.update_scan(scan_id, {
                "status": ScanStatus.PROCESSING,
                "progress": 10
            })
            
            # Create temporary directory for scan
            temp_dir = tempfile.mkdtemp(prefix=f"scan_{scan_id}_")
            
            # Process uploaded file
            logger.info(f"Processing file for scan {scan_id}")
            extracted_path = await self.file_processor.process_file(
                file_data,
                filename,
                temp_dir
            )
            
            await db.update_scan(scan_id, {"progress": 20})
            
            # Get enabled scanners
            enabled_scanners = self._get_enabled_scanners(scan_config)
            
            # Run scanners in parallel
            scan_results = await self._run_scanners(
                scan_id,
                extracted_path,
                enabled_scanners,
                scan_config
            )
            
            # Process and normalize results
            logger.info(f"Processing results for scan {scan_id}")
            processed_results = await self.result_processor.process_results(
                scan_results,
                extracted_path
            )
            
            await db.update_scan(scan_id, {"progress": 90})
            
            # Store results in database
            if processed_results:
                # Add scan_id to each result
                for result in processed_results:
                    result["scan_id"] = scan_id
                    
                await db.create_scan_results_batch(processed_results)
            
            # Calculate summary statistics
            summary = self._calculate_summary(processed_results)
            
            # Update scan as completed
            await db.update_scan(scan_id, {
                "status": ScanStatus.COMPLETED,
                "progress": 100,
                "completed_at": datetime.utcnow().isoformat(),
                "summary": summary,
                "total_findings": len(processed_results)
            })
            
            logger.info(f"Scan {scan_id} completed successfully")
            
        except asyncio.CancelledError:
            logger.info(f"Scan {scan_id} was cancelled")
            raise
            
        except Exception as e:
            logger.error(f"Scan {scan_id} failed: {e}")
            await db.update_scan(scan_id, {
                "status": ScanStatus.FAILED,
                "error": str(e),
                "completed_at": datetime.utcnow().isoformat()
            })
            
        finally:
            # Clean up temporary files
            if temp_dir and os.path.exists(temp_dir):
                self.file_processor.cleanup_directory(temp_dir)
    
    async def _run_scanners(
        self,
        scan_id: str,
        target_path: str,
        enabled_scanners: List[str],
        scan_config: Optional[Dict[str, Any]] = None
    ) -> Dict[str, List[Dict[str, Any]]]:
        """
        Run enabled scanners in parallel.
        
        Args:
            scan_id: ID of the current scan
            target_path: Path to the code to scan
            enabled_scanners: List of scanner types to run
            scan_config: Optional scan configuration
            
        Returns:
            Dict mapping scanner type to list of findings
        """
        results = {}
        tasks = []
        
        total_scanners = len(enabled_scanners)
        progress_per_scanner = 60 / total_scanners  # 60% of progress for scanning
        current_progress = 20
        
        for scanner_type in enabled_scanners:
            if scanner_type in self.scanners:
                scanner = self.scanners[scanner_type]
                task = self._run_single_scanner(
                    scanner,
                    scanner_type,
                    target_path,
                    scan_config
                )
                tasks.append((scanner_type, task))
        
        # Run scanners concurrently
        for scanner_type, task in tasks:
            try:
                logger.info(f"Running {scanner_type} scanner for scan {scan_id}")
                result = await task
                results[scanner_type] = result
                
                current_progress += progress_per_scanner
                await db.update_scan(scan_id, {"progress": int(current_progress)})
                
            except Exception as e:
                logger.error(f"Scanner {scanner_type} failed: {e}")
                results[scanner_type] = []
        
        return results
    
    async def _run_single_scanner(
        self,
        scanner: Any,
        scanner_type: str,
        target_path: str,
        scan_config: Optional[Dict[str, Any]] = None
    ) -> List[Dict[str, Any]]:
        """
        Run a single scanner with error handling.
        
        Args:
            scanner: Scanner instance
            scanner_type: Type of scanner
            target_path: Path to scan
            scan_config: Optional configuration
            
        Returns:
            List of findings from the scanner
        """
        try:
            # Get scanner-specific config
            scanner_config = {}
            if scan_config and "scanners" in scan_config:
                scanner_config = scan_config["scanners"].get(scanner_type, {})
            
            return await scanner.scan(target_path, scanner_config)
            
        except Exception as e:
            logger.error(f"Scanner {scanner_type} failed: {e}")
            return []
    
    def _get_enabled_scanners(
        self,
        scan_config: Optional[Dict[str, Any]] = None
    ) -> List[str]:
        """
        Get list of enabled scanners based on configuration.
        
        Args:
            scan_config: Optional scan configuration
            
        Returns:
            List of enabled scanner types
        """
        if not scan_config or "enabled_scanners" not in scan_config:
            # Default: enable all scanners
            return list(ScannerType)
        
        enabled = []
        for scanner_type in scan_config["enabled_scanners"]:
            if scanner_type in ScannerType.__members__.values():
                enabled.append(scanner_type)
                
        return enabled
    
    def _calculate_summary(
        self,
        results: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Calculate summary statistics from scan results.
        
        Args:
            results: List of processed scan results
            
        Returns:
            Dict containing summary statistics
        """
        summary = {
            "total": len(results),
            "by_severity": {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "info": 0
            },
            "by_category": {},
            "by_scanner": {}
        }
        
        for result in results:
            # Count by severity
            severity = result.get("severity", "info").lower()
            if severity in summary["by_severity"]:
                summary["by_severity"][severity] += 1
            
            # Count by category
            category = result.get("category", "unknown")
            if category not in summary["by_category"]:
                summary["by_category"][category] = 0
            summary["by_category"][category] += 1
            
            # Count by scanner
            scanner = result.get("scanner", "unknown")
            if scanner not in summary["by_scanner"]:
                summary["by_scanner"][scanner] = 0
            summary["by_scanner"][scanner] += 1
        
        return summary


# Create global scanner service instance
scanner_service = ScannerService()