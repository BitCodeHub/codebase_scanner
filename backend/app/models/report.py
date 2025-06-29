from sqlalchemy import Column, String, Integer, ForeignKey, DateTime, Text, JSON, Boolean
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
from app.utils.database import Base

class Report(Base):
    __tablename__ = "reports"
    
    id = Column(Integer, primary_key=True, index=True)
    project_id = Column(Integer, ForeignKey("projects.id"), nullable=False)
    scan_id = Column(Integer, ForeignKey("scans.id"), unique=True, nullable=False)
    
    # Report metadata
    title = Column(String, nullable=False)
    report_type = Column(String)  # security, compliance, executive
    format = Column(String, default="json")  # json, pdf, sarif
    
    # Content
    summary = Column(Text)
    detailed_findings = Column(JSON)
    statistics = Column(JSON)
    compliance_status = Column(JSON)  # OWASP, CWE, etc.
    
    # Badge status
    launch_ready = Column(Boolean, default=False)
    security_score = Column(Integer)  # 0-100
    
    # Files
    report_file_path = Column(String)
    sarif_output = Column(JSON)
    
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Relationships
    project = relationship("Project", back_populates="reports")
    scan = relationship("Scan", back_populates="report")