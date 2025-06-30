"""
File processing utilities for handling uploads and archives.
"""

import asyncio
import hashlib
import logging
import os
import shutil
import tarfile
import tempfile
import zipfile
from pathlib import Path
from typing import Optional, Tuple, List, Set, Dict, Any
import aiofiles
import magic

logger = logging.getLogger(__name__)


class FileProcessor:
    """
    Handles file processing operations including:
    - Archive extraction
    - File type validation
    - Security checks
    - Cleanup operations
    """
    
    # Maximum file size (500MB)
    MAX_FILE_SIZE = 500 * 1024 * 1024
    
    # Maximum extraction size (2GB)
    MAX_EXTRACTION_SIZE = 2 * 1024 * 1024 * 1024
    
    # Allowed archive types
    ARCHIVE_TYPES = {
        'application/zip': ['.zip'],
        'application/x-zip-compressed': ['.zip'],
        'application/x-tar': ['.tar'],
        'application/x-gzip': ['.gz', '.tgz', '.tar.gz'],
        'application/x-bzip2': ['.bz2', '.tbz2', '.tar.bz2'],
        'application/x-xz': ['.xz', '.tar.xz'],
        'application/x-7z-compressed': ['.7z']
    }
    
    # Dangerous file patterns to exclude
    DANGEROUS_PATTERNS = {
        '__pycache__',
        '.git/objects',
        'node_modules',
        '.env.local',
        '.env.production',
        '*.pyc',
        '*.pyo',
        '*.egg-info',
        '.DS_Store',
        'Thumbs.db'
    }
    
    # File extensions to process
    CODE_EXTENSIONS = {
        '.py', '.js', '.ts', '.jsx', '.tsx', '.java', '.c', '.cpp', '.h',
        '.cs', '.go', '.rs', '.php', '.rb', '.swift', '.kt', '.scala',
        '.r', '.m', '.mm', '.sh', '.bash', '.ps1', '.yaml', '.yml',
        '.json', '.xml', '.html', '.css', '.scss', '.sql', '.tf'
    }
    
    def __init__(self):
        """Initialize file processor."""
        self.mime = magic.Magic(mime=True)
    
    async def process_file(
        self,
        file_data: bytes,
        filename: str,
        output_dir: str
    ) -> str:
        """
        Process uploaded file and extract if necessary.
        
        Args:
            file_data: Raw file data
            filename: Original filename
            output_dir: Directory to extract files to
            
        Returns:
            Path to processed files
            
        Raises:
            ValueError: If file validation fails
            OSError: If extraction fails
        """
        # Validate file size
        if len(file_data) > self.MAX_FILE_SIZE:
            raise ValueError(f"File size exceeds maximum allowed size of {self.MAX_FILE_SIZE / 1024 / 1024}MB")
        
        # Save file temporarily
        temp_file = os.path.join(output_dir, "upload_" + self._sanitize_filename(filename))
        async with aiofiles.open(temp_file, 'wb') as f:
            await f.write(file_data)
        
        # Detect file type
        file_type = self.mime.from_file(temp_file)
        logger.info(f"Processing file {filename} with type {file_type}")
        
        # Check if it's an archive
        if self._is_archive(file_type, filename):
            # Extract archive
            extract_dir = os.path.join(output_dir, "extracted")
            os.makedirs(extract_dir, exist_ok=True)
            
            await self._extract_archive(temp_file, extract_dir, file_type)
            os.unlink(temp_file)  # Remove temporary file
            
            # Validate extracted content
            self._validate_extracted_files(extract_dir)
            
            return extract_dir
        else:
            # Single file - check if it's a code file
            if self._is_code_file(filename):
                # Move to extraction directory
                extract_dir = os.path.join(output_dir, "extracted")
                os.makedirs(extract_dir, exist_ok=True)
                
                final_path = os.path.join(extract_dir, self._sanitize_filename(filename))
                shutil.move(temp_file, final_path)
                
                return extract_dir
            else:
                raise ValueError(f"Unsupported file type: {file_type}")
    
    async def _extract_archive(
        self,
        archive_path: str,
        extract_dir: str,
        file_type: str
    ) -> None:
        """
        Extract archive contents safely.
        
        Args:
            archive_path: Path to archive file
            extract_dir: Directory to extract to
            file_type: MIME type of archive
            
        Raises:
            OSError: If extraction fails
            ValueError: If archive is malicious
        """
        total_size = 0
        file_count = 0
        
        try:
            if file_type in ['application/zip', 'application/x-zip-compressed']:
                # Extract ZIP
                with zipfile.ZipFile(archive_path, 'r') as zf:
                    # Check for zip bombs
                    for info in zf.infolist():
                        total_size += info.file_size
                        file_count += 1
                        
                        if total_size > self.MAX_EXTRACTION_SIZE:
                            raise ValueError("Archive extraction size exceeds limit")
                        
                        if file_count > 10000:
                            raise ValueError("Archive contains too many files")
                        
                        # Check for path traversal
                        if self._is_path_traversal(info.filename):
                            logger.warning(f"Skipping potentially malicious path: {info.filename}")
                            continue
                        
                        # Skip dangerous files
                        if self._is_dangerous_file(info.filename):
                            continue
                        
                        # Extract file
                        target_path = os.path.join(extract_dir, info.filename)
                        os.makedirs(os.path.dirname(target_path), exist_ok=True)
                        
                        with zf.open(info) as source, open(target_path, 'wb') as target:
                            shutil.copyfileobj(source, target)
            
            elif file_type == 'application/x-tar' or 'tar' in archive_path.lower():
                # Extract TAR and variants
                mode = 'r'
                if archive_path.endswith('.gz') or archive_path.endswith('.tgz'):
                    mode = 'r:gz'
                elif archive_path.endswith('.bz2') or archive_path.endswith('.tbz2'):
                    mode = 'r:bz2'
                elif archive_path.endswith('.xz'):
                    mode = 'r:xz'
                
                with tarfile.open(archive_path, mode) as tf:
                    # Check for tar bombs
                    for member in tf.getmembers():
                        total_size += member.size
                        file_count += 1
                        
                        if total_size > self.MAX_EXTRACTION_SIZE:
                            raise ValueError("Archive extraction size exceeds limit")
                        
                        if file_count > 10000:
                            raise ValueError("Archive contains too many files")
                        
                        # Check for path traversal
                        if self._is_path_traversal(member.name):
                            logger.warning(f"Skipping potentially malicious path: {member.name}")
                            continue
                        
                        # Skip dangerous files
                        if self._is_dangerous_file(member.name):
                            continue
                        
                        # Extract file
                        tf.extract(member, extract_dir)
            
            else:
                raise ValueError(f"Unsupported archive type: {file_type}")
                
        except Exception as e:
            logger.error(f"Failed to extract archive: {e}")
            raise
    
    def _is_archive(self, file_type: str, filename: str) -> bool:
        """
        Check if file is a supported archive.
        
        Args:
            file_type: MIME type
            filename: File name
            
        Returns:
            True if file is an archive
        """
        # Check MIME type
        if file_type in self.ARCHIVE_TYPES:
            return True
        
        # Check file extension as fallback
        filename_lower = filename.lower()
        for extensions in self.ARCHIVE_TYPES.values():
            for ext in extensions:
                if filename_lower.endswith(ext):
                    return True
        
        return False
    
    def _is_code_file(self, filename: str) -> bool:
        """
        Check if file is a code file.
        
        Args:
            filename: File name
            
        Returns:
            True if file is a code file
        """
        return any(filename.lower().endswith(ext) for ext in self.CODE_EXTENSIONS)
    
    def _is_path_traversal(self, path: str) -> bool:
        """
        Check for path traversal attempts.
        
        Args:
            path: File path to check
            
        Returns:
            True if path traversal detected
        """
        # Normalize path and check for suspicious patterns
        normalized = os.path.normpath(path)
        return (
            normalized.startswith('..') or
            normalized.startswith('/') or
            normalized.startswith('\\') or
            ':' in normalized  # Windows drive letters
        )
    
    def _is_dangerous_file(self, filename: str) -> bool:
        """
        Check if file should be excluded.
        
        Args:
            filename: File name to check
            
        Returns:
            True if file is dangerous
        """
        filename_lower = filename.lower()
        
        for pattern in self.DANGEROUS_PATTERNS:
            if '*' in pattern:
                # Handle wildcard patterns
                if pattern.startswith('*'):
                    if filename_lower.endswith(pattern[1:]):
                        return True
                elif pattern.endswith('*'):
                    if filename_lower.startswith(pattern[:-1]):
                        return True
            else:
                # Exact match or path component
                if pattern in filename_lower:
                    return True
        
        return False
    
    def _sanitize_filename(self, filename: str) -> str:
        """
        Sanitize filename for safe storage.
        
        Args:
            filename: Original filename
            
        Returns:
            Sanitized filename
        """
        # Remove path components
        filename = os.path.basename(filename)
        
        # Replace dangerous characters
        safe_chars = set('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_')
        sanitized = ''.join(c if c in safe_chars else '_' for c in filename)
        
        # Ensure it's not empty
        if not sanitized:
            sanitized = 'unnamed_file'
        
        return sanitized
    
    def _validate_extracted_files(self, extract_dir: str) -> None:
        """
        Validate extracted files.
        
        Args:
            extract_dir: Directory containing extracted files
            
        Raises:
            ValueError: If no valid code files found
        """
        code_files_found = False
        
        for root, dirs, files in os.walk(extract_dir):
            for file in files:
                if self._is_code_file(file):
                    code_files_found = True
                    break
            
            if code_files_found:
                break
        
        if not code_files_found:
            raise ValueError("No code files found in the uploaded archive")
    
    def cleanup_directory(self, directory: str) -> None:
        """
        Safely clean up a directory.
        
        Args:
            directory: Directory to remove
        """
        try:
            if os.path.exists(directory) and os.path.isdir(directory):
                shutil.rmtree(directory)
                logger.info(f"Cleaned up directory: {directory}")
        except Exception as e:
            logger.error(f"Failed to cleanup directory {directory}: {e}")
    
    async def calculate_file_hash(self, file_path: str) -> str:
        """
        Calculate SHA256 hash of a file.
        
        Args:
            file_path: Path to file
            
        Returns:
            Hex digest of file hash
        """
        hash_sha256 = hashlib.sha256()
        
        async with aiofiles.open(file_path, 'rb') as f:
            while chunk := await f.read(8192):
                hash_sha256.update(chunk)
        
        return hash_sha256.hexdigest()
    
    def get_file_stats(self, directory: str) -> Dict[str, Any]:
        """
        Get statistics about files in a directory.
        
        Args:
            directory: Directory to analyze
            
        Returns:
            Dictionary with file statistics
        """
        stats = {
            "total_files": 0,
            "total_size": 0,
            "file_types": {},
            "largest_file": None,
            "code_files": 0
        }
        
        largest_size = 0
        
        for root, dirs, files in os.walk(directory):
            for file in files:
                file_path = os.path.join(root, file)
                
                try:
                    size = os.path.getsize(file_path)
                    stats["total_files"] += 1
                    stats["total_size"] += size
                    
                    # Track largest file
                    if size > largest_size:
                        largest_size = size
                        stats["largest_file"] = {
                            "path": file_path,
                            "size": size
                        }
                    
                    # Track file types
                    ext = os.path.splitext(file)[1].lower()
                    if ext:
                        stats["file_types"][ext] = stats["file_types"].get(ext, 0) + 1
                    
                    # Count code files
                    if self._is_code_file(file):
                        stats["code_files"] += 1
                        
                except OSError:
                    continue
        
        return stats