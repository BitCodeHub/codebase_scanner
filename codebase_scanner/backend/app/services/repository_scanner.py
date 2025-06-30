"""
Repository scanning service for cloning and scanning GitHub repositories.
"""

import os
import tempfile
import shutil
import asyncio
import uuid
from typing import Dict, Any, Optional
from urllib.parse import urlparse
import git
from datetime import datetime

from app.services.scanner_service import ScannerService
from app.database import db
from app.utils.file_processor import FileProcessor
import logging

logger = logging.getLogger(__name__)


class RepositoryScanner:
    """Service for scanning GitHub repositories."""
    
    def __init__(self, scanner_service: ScannerService):
        self.scanner_service = scanner_service
        self.file_processor = FileProcessor()
        
    async def scan_repository(
        self,
        user_id: str,
        project_id: int,
        repo_url: str,
        branch: str = "main",
        scan_config: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Clone and scan a GitHub repository.
        
        Args:
            user_id: ID of the user initiating the scan
            project_id: ID of the project being scanned
            repo_url: GitHub repository URL
            branch: Branch to scan (default: main)
            scan_config: Optional scan configuration
            
        Returns:
            Dict containing scan details including scan_id
        """
        temp_dir = None
        scan_id = str(uuid.uuid4())
        
        try:
            # Validate repository URL
            if not self._is_valid_repo_url(repo_url):
                raise ValueError("Invalid repository URL")
            
            # Create scan record in database
            scan_data = {
                "id": scan_id,
                "user_id": user_id,
                "project_id": project_id,
                "status": "pending",
                "scan_type": "repository",
                "repository_url": repo_url,
                "branch": branch,
                "config": scan_config or {},
                "started_at": datetime.utcnow().isoformat(),
                "progress": 0
            }
            
            await db.create_scan(scan_data)
            
            # Start async scan task
            scan_task = asyncio.create_task(
                self._execute_repository_scan(scan_id, repo_url, branch, scan_config)
            )
            
            return {
                "scan_id": scan_id,
                "status": "pending",
                "message": "Repository scan initiated successfully"
            }
            
        except Exception as e:
            logger.error(f"Failed to start repository scan: {e}")
            # Update scan status to failed
            await db.update_scan(scan_id, {
                "status": "failed",
                "error_message": str(e),
                "completed_at": datetime.utcnow().isoformat()
            })
            raise
    
    async def _execute_repository_scan(
        self,
        scan_id: str,
        repo_url: str,
        branch: str,
        scan_config: Optional[Dict[str, Any]] = None
    ) -> None:
        """Execute the repository scanning process."""
        temp_dir = None
        
        try:
            # Update scan status to cloning
            await db.update_scan(scan_id, {
                "status": "cloning",
                "progress": 10
            })
            
            # Create temporary directory for cloning
            temp_dir = tempfile.mkdtemp(prefix=f"repo_scan_{scan_id}_")
            
            # Clone repository
            logger.info(f"Cloning repository: {repo_url}")
            repo = await self._clone_repository(repo_url, temp_dir, branch)
            
            await db.update_scan(scan_id, {
                "status": "scanning",
                "progress": 30
            })
            
            # Get repository statistics
            file_count = self._count_files(temp_dir)
            repo_size = self._get_directory_size(temp_dir)
            
            await db.update_scan(scan_id, {
                "file_count": file_count,
                "repository_size": repo_size
            })
            
            # Use the scanner service to scan the cloned repository
            # We'll need to update the scanner service to accept a directory path
            logger.info(f"Scanning repository at: {temp_dir}")
            
            # Run scanners on the repository
            scan_results = await self.scanner_service._run_scanners(
                scan_id,
                temp_dir,
                self.scanner_service._get_enabled_scanners(scan_config),
                scan_config
            )
            
            # Process results
            processed_results = await self.scanner_service.result_processor.process_results(
                scan_results,
                temp_dir
            )
            
            await db.update_scan(scan_id, {"progress": 90})
            
            # Store results
            if processed_results:
                for result in processed_results:
                    result["scan_id"] = scan_id
                await db.create_scan_results_batch(processed_results)
            
            # Calculate summary
            summary = self.scanner_service._calculate_summary(processed_results)
            
            # Update scan as completed
            await db.update_scan(scan_id, {
                "status": "completed",
                "progress": 100,
                "completed_at": datetime.utcnow().isoformat(),
                "summary": summary,
                "total_findings": len(processed_results)
            })
            
            logger.info(f"Repository scan {scan_id} completed successfully")
            
        except Exception as e:
            logger.error(f"Repository scan {scan_id} failed: {e}")
            await db.update_scan(scan_id, {
                "status": "failed",
                "error_message": str(e),
                "completed_at": datetime.utcnow().isoformat()
            })
            
        finally:
            # Clean up temporary files
            if temp_dir and os.path.exists(temp_dir):
                shutil.rmtree(temp_dir, ignore_errors=True)
    
    async def _clone_repository(self, repo_url: str, target_dir: str, branch: str) -> git.Repo:
        """Clone a repository to the target directory."""
        try:
            # Run git clone in a thread pool to avoid blocking
            loop = asyncio.get_event_loop()
            repo = await loop.run_in_executor(
                None,
                lambda: git.Repo.clone_from(
                    repo_url,
                    target_dir,
                    branch=branch,
                    depth=1  # Shallow clone for speed
                )
            )
            return repo
        except Exception as e:
            logger.error(f"Failed to clone repository: {e}")
            raise
    
    def _is_valid_repo_url(self, url: str) -> bool:
        """Validate if the URL is a valid GitHub repository URL."""
        try:
            parsed = urlparse(url)
            # Support GitHub, GitLab, Bitbucket
            valid_hosts = ['github.com', 'gitlab.com', 'bitbucket.org']
            return parsed.scheme in ['http', 'https'] and any(host in parsed.netloc for host in valid_hosts)
        except:
            return False
    
    def _count_files(self, directory: str) -> int:
        """Count the number of files in a directory."""
        count = 0
        for root, dirs, files in os.walk(directory):
            # Skip hidden directories
            dirs[:] = [d for d in dirs if not d.startswith('.')]
            count += len(files)
        return count
    
    def _get_directory_size(self, directory: str) -> int:
        """Get the total size of a directory in bytes."""
        total_size = 0
        for root, dirs, files in os.walk(directory):
            for file in files:
                file_path = os.path.join(root, file)
                try:
                    total_size += os.path.getsize(file_path)
                except:
                    pass
        return total_size