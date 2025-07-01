"""
Simplified Celery application for initial deployment
"""
import os
import sys
from celery import Celery

# Get Redis URL and ensure it has database number
redis_url = os.getenv('REDIS_URL', 'redis://localhost:6379/0')
if redis_url and not redis_url.endswith('/0'):
    redis_url = redis_url.rstrip('/') + '/0'

print(f"[Simple Celery] Using REDIS_URL: {redis_url}", file=sys.stderr)

# Create Celery instance
celery = Celery(
    'codebase_scanner',
    broker=redis_url,
    backend=redis_url
)

# Configure Celery
celery.conf.update(
    task_serializer='json',
    accept_content=['json'],
    result_serializer='json',
    timezone='UTC',
    enable_utc=True,
    task_routes={
        'app.tasks.*': {'queue': 'default'},
    },
    task_default_queue='default',
    task_default_exchange='default',
    task_default_exchange_type='direct',
    worker_log_format='[%(asctime)s: %(levelname)s/%(processName)s] %(message)s',
    worker_task_log_format='[%(asctime)s: %(levelname)s/%(processName)s][%(task_name)s(%(task_id)s)] %(message)s',
    # Disable auto-discovery of tasks
    imports=(),
    include=(),
)

@celery.task
def health_check():
    """Simple health check task"""
    return {
        'status': 'healthy',
        'message': 'Celery worker is running',
        'note': 'Running in minimal mode - configure environment variables for full functionality'
    }

@celery.task
def test_task(x, y):
    """Simple test task that adds two numbers"""
    return x + y

# This allows the worker to start without importing the full application
if __name__ == '__main__':
    celery.start()