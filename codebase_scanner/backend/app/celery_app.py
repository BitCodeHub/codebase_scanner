"""
Celery configuration for background task processing.
"""
import os
import sys
from celery import Celery
from celery.signals import setup_logging
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Get Redis URL from environment
redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/0")
print(f"[Celery Config] REDIS_URL from env: {redis_url}", file=sys.stderr)
print(f"[Celery Config] All env vars with REDIS: {[k for k in os.environ.keys() if 'REDIS' in k]}", file=sys.stderr)

# Create Celery instance
celery_app = Celery(
    "codebase_scanner",
    broker=redis_url,
    backend=redis_url,
    include=["app.tasks.scan_tasks", "app.tasks.ai_tasks"]
)

# Celery configuration
celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    result_expires=3600,  # Results expire after 1 hour
    task_track_started=True,
    task_time_limit=1800,  # 30 minutes max per task
    task_soft_time_limit=1500,  # 25 minutes soft limit
    worker_prefetch_multiplier=1,  # Disable prefetching for long tasks
    worker_max_tasks_per_child=10,  # Restart worker after 10 tasks
)

# Configure queues
celery_app.conf.task_routes = {
    "app.tasks.scan_tasks.*": {"queue": "scans"},
    "app.tasks.ai_tasks.*": {"queue": "ai"},
    "app.tasks.export_tasks.*": {"queue": "exports"},
}

# Disable Celery's own logging config
@setup_logging.connect
def config_loggers(*args, **kwargs):
    from src.utils.logging import setup_logging
    setup_logging()

if __name__ == "__main__":
    celery_app.start()