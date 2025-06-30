"""
Production logging configuration for the security scanner.
"""
import logging
import logging.handlers
import sys
import os
from datetime import datetime
from typing import Dict, Any
import json
import traceback
from functools import wraps
import asyncio

# Log levels
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
LOG_FORMAT = os.getenv("LOG_FORMAT", "json")  # json or text

class JSONFormatter(logging.Formatter):
    """Custom JSON formatter for structured logging."""
    
    def format(self, record: logging.LogRecord) -> str:
        log_data = {
            "timestamp": datetime.utcnow().isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }
        
        # Add extra fields
        if hasattr(record, "user_id"):
            log_data["user_id"] = record.user_id
        if hasattr(record, "scan_id"):
            log_data["scan_id"] = record.scan_id
        if hasattr(record, "project_id"):
            log_data["project_id"] = record.project_id
            
        # Add exception info if present
        if record.exc_info:
            log_data["exception"] = {
                "type": record.exc_info[0].__name__,
                "message": str(record.exc_info[1]),
                "traceback": traceback.format_exception(*record.exc_info)
            }
            
        return json.dumps(log_data)

def setup_logging():
    """Setup production logging configuration."""
    # Create formatters
    if LOG_FORMAT == "json":
        formatter = JSONFormatter()
    else:
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
    
    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    
    # File handler with rotation
    log_dir = os.getenv("LOG_DIR", "logs")
    if not os.path.isabs(log_dir):
        # Use relative path from backend directory
        from pathlib import Path
        log_dir = Path(__file__).parent.parent.parent / log_dir
    os.makedirs(log_dir, exist_ok=True)
    
    file_handler = logging.handlers.RotatingFileHandler(
        os.path.join(log_dir, "app.log"),
        maxBytes=10 * 1024 * 1024,  # 10MB
        backupCount=5
    )
    file_handler.setFormatter(formatter)
    
    # Error file handler
    error_handler = logging.handlers.RotatingFileHandler(
        os.path.join(log_dir, "error.log"),
        maxBytes=10 * 1024 * 1024,  # 10MB
        backupCount=5
    )
    error_handler.setLevel(logging.ERROR)
    error_handler.setFormatter(formatter)
    
    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, LOG_LEVEL))
    root_logger.addHandler(console_handler)
    root_logger.addHandler(file_handler)
    root_logger.addHandler(error_handler)
    
    # Configure specific loggers
    logging.getLogger("uvicorn").setLevel(logging.INFO)
    logging.getLogger("fastapi").setLevel(logging.INFO)
    
    # Suppress noisy libraries
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)

def get_logger(name: str) -> logging.Logger:
    """Get a logger instance with the given name."""
    return logging.getLogger(name)

def log_execution(logger: logging.Logger = None):
    """Decorator to log function execution."""
    def decorator(func):
        @wraps(func)
        async def async_wrapper(*args, **kwargs):
            nonlocal logger
            if logger is None:
                logger = get_logger(func.__module__)
                
            start_time = datetime.utcnow()
            logger.info(f"Starting {func.__name__}", extra={
                "function": func.__name__,
                "args": str(args)[:200],  # Truncate long args
                "kwargs": str(kwargs)[:200]
            })
            
            try:
                result = await func(*args, **kwargs)
                duration = (datetime.utcnow() - start_time).total_seconds()
                logger.info(f"Completed {func.__name__}", extra={
                    "function": func.__name__,
                    "duration_seconds": duration,
                    "success": True
                })
                return result
            except Exception as e:
                duration = (datetime.utcnow() - start_time).total_seconds()
                logger.error(f"Failed {func.__name__}", extra={
                    "function": func.__name__,
                    "duration_seconds": duration,
                    "success": False,
                    "error": str(e)
                }, exc_info=True)
                raise
                
        @wraps(func)
        def sync_wrapper(*args, **kwargs):
            nonlocal logger
            if logger is None:
                logger = get_logger(func.__module__)
                
            start_time = datetime.utcnow()
            logger.info(f"Starting {func.__name__}", extra={
                "function": func.__name__,
                "args": str(args)[:200],
                "kwargs": str(kwargs)[:200]
            })
            
            try:
                result = func(*args, **kwargs)
                duration = (datetime.utcnow() - start_time).total_seconds()
                logger.info(f"Completed {func.__name__}", extra={
                    "function": func.__name__,
                    "duration_seconds": duration,
                    "success": True
                })
                return result
            except Exception as e:
                duration = (datetime.utcnow() - start_time).total_seconds()
                logger.error(f"Failed {func.__name__}", extra={
                    "function": func.__name__,
                    "duration_seconds": duration,
                    "success": False,
                    "error": str(e)
                }, exc_info=True)
                raise
                
        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        else:
            return sync_wrapper
    return decorator

class SecurityLogger:
    """Specialized logger for security events."""
    
    def __init__(self):
        self.logger = get_logger("security")
        
    def log_scan_started(self, scan_id: str, user_id: str, file_name: str):
        """Log scan initiation."""
        self.logger.info("Security scan started", extra={
            "event": "scan_started",
            "scan_id": scan_id,
            "user_id": user_id,
            "file_name": file_name
        })
        
    def log_vulnerability_found(self, scan_id: str, vulnerability: Dict[str, Any]):
        """Log vulnerability discovery."""
        self.logger.warning("Vulnerability found", extra={
            "event": "vulnerability_found",
            "scan_id": scan_id,
            "severity": vulnerability.get("severity"),
            "type": vulnerability.get("vulnerability_type"),
            "file": vulnerability.get("file_path")
        })
        
    def log_scan_completed(self, scan_id: str, duration: float, total_findings: int):
        """Log scan completion."""
        self.logger.info("Security scan completed", extra={
            "event": "scan_completed",
            "scan_id": scan_id,
            "duration_seconds": duration,
            "total_findings": total_findings
        })
        
    def log_authentication_attempt(self, email: str, success: bool, ip_address: str = None):
        """Log authentication attempts."""
        self.logger.info("Authentication attempt", extra={
            "event": "auth_attempt",
            "email": email,
            "success": success,
            "ip_address": ip_address
        })
        
    def log_suspicious_activity(self, user_id: str, activity: str, details: Dict[str, Any]):
        """Log suspicious activities."""
        self.logger.warning("Suspicious activity detected", extra={
            "event": "suspicious_activity",
            "user_id": user_id,
            "activity": activity,
            "details": details
        })

# Initialize security logger
security_logger = SecurityLogger()

# Setup logging on module import
setup_logging()