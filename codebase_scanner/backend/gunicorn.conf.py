"""Gunicorn configuration for memory-constrained environment."""

import os
import multiprocessing

# Server socket
bind = f"0.0.0.0:{os.getenv('PORT', '8000')}"
backlog = 64

# Worker processes - critical for memory management
workers = 1  # Single worker for 512MB environment
worker_class = "uvicorn.workers.UvicornWorker"
worker_connections = 100
max_requests = 1000  # Restart workers after 1000 requests to prevent memory leaks
max_requests_jitter = 50
timeout = 120
keepalive = 5
graceful_timeout = 30

# Threading
threads = 1  # Single thread per worker

# Memory optimization
preload_app = True  # Load app before forking workers
daemon = False

# Logging
accesslog = "-"
errorlog = "-"
loglevel = os.getenv("LOG_LEVEL", "warning").lower()
access_log_format = '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s" %(D)s'

# Process naming
proc_name = "codebase-scanner"

# Server mechanics
worker_tmp_dir = "/dev/shm"  # Use shared memory for worker heartbeat

# SSL
keyfile = None
certfile = None

# Limit request sizes to prevent memory issues
limit_request_line = 4094
limit_request_fields = 100
limit_request_field_size = 8190


def when_ready(server):
    """Called just after the master process is initialized."""
    server.log.info("Server is ready. Spawning workers")


def worker_int(worker):
    """Called just after a worker exited on SIGINT or SIGQUIT."""
    worker.log.info("Worker interrupted")


def pre_fork(server, worker):
    """Called just before a worker is forked."""
    server.log.info(f"Pre-fork worker with pid: {worker.pid}")


def post_fork(server, worker):
    """Called just after a worker has been forked."""
    server.log.info(f"Worker spawned with pid: {worker.pid}")


def worker_abort(worker):
    """Called when a worker received the SIGABRT signal."""
    worker.log.info("Worker aborted")