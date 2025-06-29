from pydantic_settings import BaseSettings
from typing import Optional
import os

class Settings(BaseSettings):
    app_name: str = "Codebase Scanner"
    app_version: str = "1.0.0"
    debug: bool = False
    secret_key: str
    environment: str = "development"
    
    # Database
    database_url: str
    redis_url: str
    
    # API Keys
    openai_api_key: Optional[str] = None
    anthropic_api_key: Optional[str] = None
    
    # GitHub OAuth
    github_client_id: str
    github_client_secret: str
    github_redirect_uri: str
    
    # AWS
    aws_access_key_id: Optional[str] = None
    aws_secret_access_key: Optional[str] = None
    aws_region: str = "us-east-1"
    s3_bucket_name: Optional[str] = None
    
    # Queue
    celery_broker_url: str
    celery_result_backend: str
    
    # Security
    jwt_secret_key: str
    jwt_algorithm: str = "HS256"
    jwt_access_token_expire_minutes: int = 30
    
    # Email
    smtp_host: Optional[str] = None
    smtp_port: Optional[int] = 587
    smtp_user: Optional[str] = None
    smtp_password: Optional[str] = None
    
    # URLs
    frontend_url: str = "http://localhost:5173"
    api_url: str = "http://localhost:8000"
    
    # Scan limits
    max_file_size_mb: int = 100
    max_scan_duration_minutes: int = 30
    max_concurrent_scans: int = 5
    
    # Security scan settings
    enable_static_analysis: bool = True
    enable_dynamic_analysis: bool = True
    enable_ai_analysis: bool = True
    
    class Config:
        env_file = ".env"
        case_sensitive = False

settings = Settings()