"""
Database models for scan-related entities.
"""

from datetime import datetime
from typing import Dict, List, Optional, Any
from pydantic import BaseModel, Field, validator
from enum import Enum


class ScanStatus(str, Enum):
    """Scan status enumeration"""
    PENDING = "pending"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ScanSeverity(str, Enum):
    """Severity levels for findings"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ScanCategory(str, Enum):
    """Finding categories"""
    INJECTION = "injection"
    AUTHENTICATION = "authentication"
    SECRETS = "secrets"
    VULNERABLE_DEPENDENCY = "vulnerable-dependency"
    CRYPTOGRAPHY = "cryptography"
    DESERIALIZATION = "deserialization"
    PATH_TRAVERSAL = "path-traversal"
    SSRF = "ssrf"
    SECURITY_MISCONFIGURATION = "security-misconfiguration"
    SENSITIVE_DATA = "sensitive-data"
    OTHER = "other"


class ScanConfig(BaseModel):
    """Scan configuration model"""
    enabled_scanners: Optional[List[str]] = Field(
        default=None,
        description="List of scanner types to enable"
    )
    exclude_patterns: Optional[List[str]] = Field(
        default_factory=list,
        description="File patterns to exclude from scanning"
    )
    include_patterns: Optional[List[str]] = Field(
        default_factory=list,
        description="File patterns to include in scanning"
    )
    max_file_size: Optional[int] = Field(
        default=None,
        description="Maximum file size to scan in bytes"
    )
    scanners: Optional[Dict[str, Dict[str, Any]]] = Field(
        default_factory=dict,
        description="Scanner-specific configuration"
    )


class ScanCreate(BaseModel):
    """Model for creating a new scan"""
    project_id: int = Field(..., description="ID of the project to scan")
    config: Optional[ScanConfig] = Field(
        default=None,
        description="Scan configuration"
    )


class ScanUpdate(BaseModel):
    """Model for updating scan status"""
    status: Optional[ScanStatus] = None
    progress: Optional[int] = Field(None, ge=0, le=100)
    error: Optional[str] = None
    completed_at: Optional[datetime] = None
    summary: Optional[Dict[str, Any]] = None
    total_findings: Optional[int] = None


class ScanResult(BaseModel):
    """Model for a scan finding/result"""
    scan_id: str = Field(..., description="ID of the scan")
    scanner: str = Field(..., description="Scanner that found the issue")
    rule_id: str = Field(..., description="Rule or check ID")
    title: str = Field(..., description="Title of the finding")
    description: str = Field(..., description="Detailed description")
    severity: ScanSeverity = Field(..., description="Severity level")
    category: str = Field(..., description="Finding category")
    confidence: str = Field(default="MEDIUM", description="Confidence level")
    
    # Location information
    file_path: str = Field(..., description="File path where issue was found")
    line_start: int = Field(0, ge=0, description="Starting line number")
    line_end: int = Field(0, ge=0, description="Ending line number")
    column_start: int = Field(0, ge=0, description="Starting column")
    column_end: int = Field(0, ge=0, description="Ending column")
    
    # Additional information
    code_snippet: Optional[str] = Field(None, description="Code snippet")
    fix_guidance: Optional[str] = Field(None, description="How to fix the issue")
    references: List[str] = Field(default_factory=list, description="Reference URLs")
    cwe: Optional[str] = Field(None, description="CWE ID")
    owasp: Optional[str] = Field(None, description="OWASP category")
    
    # Metadata
    fingerprint: str = Field(..., description="Unique fingerprint")
    risk_score: int = Field(..., ge=0, le=100, description="Risk score")
    fix_priority: int = Field(..., ge=1, description="Fix priority")
    
    # Scanner-specific fields
    package_name: Optional[str] = None
    installed_version: Optional[str] = None
    vulnerability_id: Optional[str] = None
    cvss_score: Optional[float] = None
    secret_type: Optional[str] = None
    match: Optional[str] = None
    entropy: Optional[float] = None
    test_id: Optional[str] = None


class ScanType(str, Enum):
    """Scan type enumeration"""
    FULL = "full"
    QUICK = "quick"
    CUSTOM = "custom"


class Scan(BaseModel):
    """Complete scan model"""
    id: str = Field(..., description="Unique scan ID")
    user_id: str = Field(..., description="User who initiated the scan")
    project_id: int = Field(..., description="Project being scanned")
    status: ScanStatus = Field(..., description="Current scan status")
    filename: str = Field(..., description="Original filename")
    file_size: int = Field(..., description="File size in bytes")
    config: Dict[str, Any] = Field(default_factory=dict, description="Scan configuration")
    
    # Timestamps
    created_at: datetime = Field(..., description="When scan was created")
    started_at: Optional[datetime] = Field(None, description="When scan started")
    completed_at: Optional[datetime] = Field(None, description="When scan completed")
    
    # Progress and results
    progress: int = Field(0, ge=0, le=100, description="Scan progress percentage")
    total_findings: int = Field(0, ge=0, description="Total number of findings")
    summary: Optional[Dict[str, Any]] = Field(None, description="Summary statistics")
    error: Optional[str] = Field(None, description="Error message if failed")
    
    # Scanner information
    scanners: List[str] = Field(default_factory=list, description="Enabled scanners")
    
    class Config:
        json_schema_extra = {
            "example": {
                "id": "550e8400-e29b-41d4-a716-446655440000",
                "user_id": "user123",
                "project_id": 1,
                "status": "completed",
                "filename": "myapp.zip",
                "file_size": 1048576,
                "progress": 100,
                "total_findings": 15,
                "summary": {
                    "by_severity": {
                        "critical": 2,
                        "high": 5,
                        "medium": 6,
                        "low": 2
                    }
                }
            }
        }


class ScanListResponse(BaseModel):
    """Response model for listing scans"""
    scans: List[Scan]
    total: int
    limit: int
    offset: int
    
    class Config:
        json_schema_extra = {
            "example": {
                "scans": [Scan.Config.json_schema_extra["example"]],
                "total": 50,
                "limit": 10,
                "offset": 0
            }
        }


class ScanResultsResponse(BaseModel):
    """Response model for scan results"""
    results: List[ScanResult]
    total: int
    scan_id: str
    filters: Optional[Dict[str, Any]] = None
    
    class Config:
        json_schema_extra = {
            "example": {
                "results": [
                    {
                        "scan_id": "550e8400-e29b-41d4-a716-446655440000",
                        "scanner": "semgrep",
                        "rule_id": "python.lang.security.insecure-hash.insecure-hash",
                        "title": "Use of insecure MD5 hash",
                        "description": "MD5 is cryptographically broken",
                        "severity": "high",
                        "category": "cryptography",
                        "file_path": "app/utils/crypto.py",
                        "line_start": 15,
                        "line_end": 15,
                        "risk_score": 75,
                        "fix_priority": 2
                    }
                ],
                "total": 15,
                "scan_id": "550e8400-e29b-41d4-a716-446655440000"
            }
        }


class ScanResponse(BaseModel):
    """Response model for scan creation/retrieval"""
    id: str
    project_id: str
    scan_type: ScanType
    status: ScanStatus
    created_at: str
    message: Optional[str] = None
    repository_url: Optional[str] = None
    branch: Optional[str] = None
    scan_id: Optional[str] = None
    file_name: Optional[str] = None
    file_size: Optional[int] = None
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    progress: Optional[int] = 0
    total_findings: Optional[int] = 0
    error_message: Optional[str] = None


class ScanResultResponse(BaseModel):
    """Response model for individual scan results"""
    id: Optional[str] = None
    scan_id: str
    scanner: str
    rule_id: str
    title: str
    description: str
    severity: ScanSeverity
    category: str
    confidence: str = "MEDIUM"
    file_path: str
    line_start: int = 0
    line_end: int = 0
    column_start: int = 0
    column_end: int = 0
    code_snippet: Optional[str] = None
    fix_guidance: Optional[str] = None
    references: List[str] = Field(default_factory=list)
    cwe: Optional[str] = None
    owasp: Optional[str] = None
    fingerprint: Optional[str] = None
    risk_score: Optional[int] = None
    fix_priority: Optional[int] = None
    created_at: Optional[str] = None


class ScanProgressResponse(BaseModel):
    """Response model for scan progress"""
    scan_id: str
    status: ScanStatus
    progress: int = Field(ge=0, le=100)
    current_scanner: Optional[str] = None
    completed_scanners: List[str] = Field(default_factory=list)
    pending_scanners: List[str] = Field(default_factory=list)
    messages: List[str] = Field(default_factory=list)
    started_at: Optional[str] = None
    estimated_time_remaining: Optional[int] = None