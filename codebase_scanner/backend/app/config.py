from pydantic_settings import BaseSettings
from pydantic import Field
from typing import Optional
import os

class Settings(BaseSettings):
    """Application settings with Supabase integration"""
    
    # Application
    app_name: str = "Codebase Scanner API"
    app_version: str = "1.0.0"
    environment: str = Field(default="development", env="PYTHON_ENV")
    debug: bool = Field(default=True, env="DEBUG")
    
    # Security
    secret_key: str = Field(default="temporary-secret-key-replace-in-production", env="SECRET_KEY")
    algorithm: str = Field(default="HS256", env="ALGORITHM")
    access_token_expire_minutes: int = Field(default=30, env="ACCESS_TOKEN_EXPIRE_MINUTES")
    
    # Supabase Configuration - Optional for initial deployment
    supabase_url: Optional[str] = Field(default=None, env="SUPABASE_URL")
    supabase_anon_key: Optional[str] = Field(default=None, env="SUPABASE_ANON_KEY")
    supabase_service_key: Optional[str] = Field(default=None, env="SUPABASE_SERVICE_KEY")
    
    # Redis for background tasks
    redis_url: str = Field(default="redis://localhost:6379", env="REDIS_URL")
    
    # File Upload
    upload_dir: str = Field(default="uploads", env="UPLOAD_DIR")
    max_file_size: int = Field(default=100 * 1024 * 1024, env="MAX_FILE_SIZE")  # 100MB
    allowed_file_types: list = Field(default=[".zip", ".tar", ".tar.gz", ".tgz"])
    
    # Scanning
    max_scan_time: int = Field(default=3600, env="MAX_SCAN_TIME")  # 1 hour
    max_concurrent_scans: int = Field(default=5, env="MAX_CONCURRENT_SCANS")
    
    # CORS
    frontend_url: str = Field(default="http://localhost:5173", env="FRONTEND_URL")
    allowed_origins: list = Field(default=["http://localhost:5173"])
    
    # Logging
    log_level: str = Field(default="INFO", env="LOG_LEVEL")
    
    class Config:
        env_file = ".env"
        case_sensitive = False

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        
        # Check for SUPABASE_SERVICE_ROLE_KEY if SUPABASE_SERVICE_KEY is not set
        if not self.supabase_service_key and os.getenv("SUPABASE_SERVICE_ROLE_KEY"):
            self.supabase_service_key = os.getenv("SUPABASE_SERVICE_ROLE_KEY")
        
        # Ensure upload directory exists
        os.makedirs(self.upload_dir, exist_ok=True)

# Global settings instance
settings = Settings()