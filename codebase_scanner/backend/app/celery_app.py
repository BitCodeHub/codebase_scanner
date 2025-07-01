"""
Celery configuration for background task processing.
"""
import os
import sys
from celery import Celery
from celery.signals import setup_logging

# Don't load dotenv on production - Render provides env vars directly
if os.getenv('RENDER') != 'true':
    from dotenv import load_dotenv
    load_dotenv()

# Get Redis URL from environment
redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/0")

# Ensure Redis URL has a database number if it doesn't
if redis_url and not redis_url.endswith('/0'):
    if '?' in redis_url:
        # If there are query parameters, insert /0 before them
        parts = redis_url.split('?')
        redis_url = parts[0] + '/0?' + parts[1]
    else:
        # Otherwise just append /0
        redis_url = redis_url + '/0'

print(f"[Celery Config] REDIS_URL from env: {os.getenv('REDIS_URL')}", file=sys.stderr)
print(f"[Celery Config] REDIS_URL for Celery: {redis_url}", file=sys.stderr)
print(f"[Celery Config] All env vars with REDIS: {[k for k in os.environ.keys() if 'REDIS' in k]}", file=sys.stderr)

# Create Celery instance
celery_app = Celery(
    "codebase_scanner",
    broker=redis_url,
    backend=redis_url,
    include=["app.tasks.scan_tasks", "app.tasks.ai_tasks"]
)

# Celery configuration - optimized for low memory
celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    result_expires=1800,  # Results expire after 30 minutes
    task_track_started=True,
    task_time_limit=1800,  # 30 minutes max per task
    task_soft_time_limit=1500,  # 25 minutes soft limit
    worker_prefetch_multiplier=1,  # Disable prefetching for long tasks
    worker_max_tasks_per_child=1,  # Restart worker after each task to free memory
    worker_disable_rate_limits=True,  # Save memory by disabling rate limits
    task_compression="gzip",  # Compress task data to save memory
    result_compression="gzip",  # Compress results to save memory
    broker_connection_retry_on_startup=True,
    broker_connection_retry=True,
    broker_connection_max_retries=10,
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