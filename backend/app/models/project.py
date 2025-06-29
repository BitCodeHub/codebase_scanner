from sqlalchemy import Column, String, Integer, ForeignKey, DateTime, Text, Boolean, JSON
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
from app.utils.database import Base

class Project(Base):
    __tablename__ = "projects"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    description = Column(Text)
    owner_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    
    # GitHub integration
    github_repo_url = Column(String)
    github_repo_id = Column(String, unique=True, index=True)
    github_default_branch = Column(String, default="main")
    
    # Upload option
    uploaded_file_path = Column(String)
    
    # Configuration
    scan_config = Column(JSON, default={})
    excluded_paths = Column(JSON, default=[])
    is_public = Column(Boolean, default=False)
    
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    last_scan_at = Column(DateTime(timezone=True))
    
    # Relationships
    owner = relationship("User", back_populates="projects")
    scans = relationship("Scan", back_populates="project", cascade="all, delete-orphan")
    reports = relationship("Report", back_populates="project", cascade="all, delete-orphan")