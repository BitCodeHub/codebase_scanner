"""
Supabase Storage service for file management.
"""
import os
import uuid
import hashlib
from datetime import datetime
from typing import Optional, BinaryIO, Dict, Any
from pathlib import Path

from src.database import get_supabase_client
from src.utils.logging import get_logger

logger = get_logger(__name__)

class StorageService:
    """Service for managing file storage in Supabase."""
    
    def __init__(self):
        self.supabase = get_supabase_client()
        self.bucket_name = os.getenv("SUPABASE_STORAGE_BUCKET", "scan-files")
        self._ensure_bucket_exists()
    
    def _ensure_bucket_exists(self):
        """Ensure the storage bucket exists."""
        try:
            buckets = self.supabase.storage.list_buckets()
            bucket_names = [b.name for b in buckets]
            
            if self.bucket_name not in bucket_names:
                self.supabase.storage.create_bucket(
                    self.bucket_name,
                    options={
                        "public": False,
                        "allowed_mime_types": [
                            "application/zip",
                            "application/x-tar",
                            "application/gzip",
                            "application/x-gzip",
                            "text/plain",
                            "application/octet-stream"
                        ],
                        "file_size_limit": 524288000  # 500MB
                    }
                )
                logger.info(f"Created storage bucket: {self.bucket_name}")
        except Exception as e:
            logger.error(f"Failed to ensure bucket exists: {e}")
    
    async def upload_scan_file(
        self,
        file_data: bytes,
        filename: str,
        scan_id: str,
        user_id: str
    ) -> Dict[str, Any]:
        """
        Upload a scan file to Supabase Storage.
        
        Args:
            file_data: File content as bytes
            filename: Original filename
            scan_id: Associated scan ID
            user_id: User who uploaded the file
            
        Returns:
            Dict with file metadata and storage path
        """
        try:
            # Generate unique storage path
            file_extension = Path(filename).suffix
            file_hash = hashlib.sha256(file_data).hexdigest()[:16]
            storage_filename = f"{scan_id}_{file_hash}{file_extension}"
            storage_path = f"{user_id}/{datetime.utcnow().strftime('%Y/%m/%d')}/{storage_filename}"
            
            # Upload to Supabase Storage
            response = self.supabase.storage.from_(self.bucket_name).upload(
                path=storage_path,
                file=file_data,
                file_options={"content-type": "application/octet-stream"}
            )
            
            # Store file metadata in database
            file_metadata = {
                "id": str(uuid.uuid4()),
                "scan_id": scan_id,
                "user_id": user_id,
                "original_filename": filename,
                "storage_path": storage_path,
                "file_size": len(file_data),
                "file_hash": file_hash,
                "mime_type": self._get_mime_type(filename),
                "uploaded_at": datetime.utcnow().isoformat()
            }
            
            self.supabase.table("scan_files").insert(file_metadata).execute()
            
            logger.info(f"Uploaded scan file: {storage_path}", extra={
                "scan_id": scan_id,
                "file_size": len(file_data),
                "storage_path": storage_path
            })
            
            return file_metadata
            
        except Exception as e:
            logger.error(f"Failed to upload scan file: {e}", exc_info=True)
            raise
    
    async def download_scan_file(self, scan_id: str, user_id: str) -> Optional[bytes]:
        """
        Download a scan file from storage.
        
        Args:
            scan_id: Scan ID to download file for
            user_id: User requesting the file
            
        Returns:
            File content as bytes or None if not found
        """
        try:
            # Get file metadata
            result = self.supabase.table("scan_files")\
                .select("*")\
                .eq("scan_id", scan_id)\
                .eq("user_id", user_id)\
                .single()\
                .execute()
            
            if not result.data:
                logger.warning(f"No file found for scan {scan_id}")
                return None
            
            file_metadata = result.data
            storage_path = file_metadata["storage_path"]
            
            # Download from storage
            file_data = self.supabase.storage.from_(self.bucket_name)\
                .download(storage_path)
            
            logger.info(f"Downloaded scan file: {storage_path}")
            return file_data
            
        except Exception as e:
            logger.error(f"Failed to download scan file: {e}", exc_info=True)
            return None
    
    async def delete_scan_file(self, scan_id: str, user_id: str) -> bool:
        """
        Delete a scan file from storage.
        
        Args:
            scan_id: Scan ID to delete file for
            user_id: User who owns the file
            
        Returns:
            True if deleted successfully
        """
        try:
            # Get file metadata
            result = self.supabase.table("scan_files")\
                .select("*")\
                .eq("scan_id", scan_id)\
                .eq("user_id", user_id)\
                .single()\
                .execute()
            
            if not result.data:
                return True  # Already deleted
            
            file_metadata = result.data
            storage_path = file_metadata["storage_path"]
            
            # Delete from storage
            self.supabase.storage.from_(self.bucket_name).remove([storage_path])
            
            # Delete metadata
            self.supabase.table("scan_files")\
                .delete()\
                .eq("id", file_metadata["id"])\
                .execute()
            
            logger.info(f"Deleted scan file: {storage_path}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to delete scan file: {e}", exc_info=True)
            return False
    
    async def get_storage_url(self, scan_id: str, user_id: str, expires_in: int = 3600) -> Optional[str]:
        """
        Get a temporary signed URL for downloading a scan file.
        
        Args:
            scan_id: Scan ID
            user_id: User requesting the URL
            expires_in: URL expiration time in seconds
            
        Returns:
            Signed URL or None
        """
        try:
            # Get file metadata
            result = self.supabase.table("scan_files")\
                .select("storage_path")\
                .eq("scan_id", scan_id)\
                .eq("user_id", user_id)\
                .single()\
                .execute()
            
            if not result.data:
                return None
            
            storage_path = result.data["storage_path"]
            
            # Generate signed URL
            response = self.supabase.storage.from_(self.bucket_name)\
                .create_signed_url(storage_path, expires_in)
            
            return response.get("signedURL")
            
        except Exception as e:
            logger.error(f"Failed to generate storage URL: {e}", exc_info=True)
            return None
    
    async def cleanup_old_files(self, days: int = 30) -> int:
        """
        Clean up old scan files from storage.
        
        Args:
            days: Number of days to keep files
            
        Returns:
            Number of files deleted
        """
        try:
            cutoff_date = datetime.utcnow() - timedelta(days=days)
            
            # Get old files
            old_files = self.supabase.table("scan_files")\
                .select("*")\
                .lt("uploaded_at", cutoff_date.isoformat())\
                .execute()
            
            deleted_count = 0
            for file_metadata in old_files.data:
                try:
                    # Delete from storage
                    self.supabase.storage.from_(self.bucket_name)\
                        .remove([file_metadata["storage_path"]])
                    
                    # Delete metadata
                    self.supabase.table("scan_files")\
                        .delete()\
                        .eq("id", file_metadata["id"])\
                        .execute()
                    
                    deleted_count += 1
                    
                except Exception as e:
                    logger.error(f"Failed to delete old file: {e}")
            
            logger.info(f"Cleaned up {deleted_count} old files")
            return deleted_count
            
        except Exception as e:
            logger.error(f"Failed to cleanup old files: {e}", exc_info=True)
            return 0
    
    def _get_mime_type(self, filename: str) -> str:
        """Get MIME type based on file extension."""
        ext = Path(filename).suffix.lower()
        mime_types = {
            ".zip": "application/zip",
            ".tar": "application/x-tar",
            ".gz": "application/gzip",
            ".tgz": "application/gzip",
            ".py": "text/x-python",
            ".js": "text/javascript",
            ".ts": "text/typescript",
            ".java": "text/x-java",
            ".c": "text/x-c",
            ".cpp": "text/x-c++",
            ".go": "text/x-go",
            ".rb": "text/x-ruby",
            ".php": "text/x-php"
        }
        return mime_types.get(ext, "application/octet-stream")