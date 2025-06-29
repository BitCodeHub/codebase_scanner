from sqlalchemy import Column, String, Integer, ForeignKey, DateTime, Text, Boolean, JSON, Enum as SQLEnum, Float
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
from app.utils.database import Base
import enum

class ScanStatus(str, enum.Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"

class ScanType(str, enum.Enum):
    SECURITY = "security"
    QUALITY = "quality"
    PERFORMANCE = "performance"
    LAUNCH_READY = "launch_ready"
    FULL = "full"

class Severity(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class Scan(Base):
    __tablename__ = "scans"
    
    id = Column(Integer, primary_key=True, index=True)
    project_id = Column(Integer, ForeignKey("projects.id"), nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    
    scan_type = Column(SQLEnum(ScanType), nullable=False)
    status = Column(SQLEnum(ScanStatus), default=ScanStatus.PENDING, nullable=False)
    
    # Scan configuration
    commit_sha = Column(String)
    branch = Column(String)
    triggered_by = Column(String)  # manual, webhook, scheduled
    scan_config = Column(JSON, default={})
    
    # Timing
    started_at = Column(DateTime(timezone=True))
    completed_at = Column(DateTime(timezone=True))
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Results summary
    total_issues = Column(Integer, default=0)
    critical_issues = Column(Integer, default=0)
    high_issues = Column(Integer, default=0)
    medium_issues = Column(Integer, default=0)
    low_issues = Column(Integer, default=0)
    
    # Task tracking
    celery_task_id = Column(String)
    error_message = Column(Text)
    
    # Relationships
    project = relationship("Project", back_populates="scans")
    user = relationship("User", back_populates="scans")
    results = relationship("ScanResult", back_populates="scan", cascade="all, delete-orphan")
    report = relationship("Report", back_populates="scan", uselist=False)

class ScanResult(Base):
    __tablename__ = "scan_results"
    
    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)
    
    # Issue details
    rule_id = Column(String)
    title = Column(String, nullable=False)
    description = Column(Text)
    severity = Column(SQLEnum(Severity), nullable=False)
    category = Column(String)  # security, performance, quality, etc.
    
    # Location
    file_path = Column(String)
    line_number = Column(Integer)
    column_number = Column(Integer)
    code_snippet = Column(Text)
    
    # Analysis
    vulnerability_type = Column(String)  # CWE ID or type
    confidence = Column(String)  # high, medium, low
    
    # Remediation
    fix_recommendation = Column(Text)
    ai_generated_fix = Column(Text)
    references = Column(JSON, default=[])
    remediation_example = Column(Text)
    
    # Risk Assessment
    cvss_score = Column(Float)
    cvss_vector = Column(String)
    risk_rating = Column(String)
    exploitability = Column(Text)
    impact = Column(Text)
    likelihood = Column(String)
    
    # Compliance & Standards
    owasp_category = Column(String)
    compliance_mappings = Column(JSON, default={})
    
    # Development Impact
    fix_effort = Column(String)  # Low, Medium, High
    fix_priority = Column(Integer)  # 1-5, 1 being highest
    
    # Additional Context
    code_context = Column(JSON)  # Lines before and after
    tags = Column(JSON, default=[])
    confidence = Column(String, default='medium')  # low, medium, high
    
    # Affected Dependencies
    affected_packages = Column(JSON, default=[])  # List of affected npm/pip packages
    vulnerable_versions = Column(JSON, default={})  # Package -> version ranges
    fixed_versions = Column(JSON, default={})  # Package -> fixed version
    dependency_chain = Column(JSON, default=[])  # How the vulnerability propagates
    
    # Metadata
    analyzer = Column(String)  # semgrep, bandit, ai, etc.
    raw_output = Column(JSON)
    false_positive = Column(Boolean, default=False)
    
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Relationships
    scan = relationship("Scan", back_populates="results")