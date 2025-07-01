#!/usr/bin/env python3
"""
Lightweight Celery worker startup script optimized for low memory environments.
"""
import os
import sys
import gc
import subprocess

# Force garbage collection
gc.collect()

# Set memory-efficient Python options
os.environ['PYTHONOPTIMIZE'] = '1'  # Remove docstrings
os.environ['PYTHONDONTWRITEBYTECODE'] = '1'  # Don't create .pyc files
os.environ['MALLOC_ARENA_MAX'] = '2'  # Limit memory fragmentation

print("=== MEMORY-OPTIMIZED WORKER STARTUP ===", file=sys.stderr)
print(f"Current directory: {os.getcwd()}", file=sys.stderr)
print(f"REDIS_URL: {os.getenv('REDIS_URL', 'NOT SET')}", file=sys.stderr)

# Add current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Test Redis connection with minimal imports
redis_url = os.getenv('REDIS_URL', 'redis://localhost:6379/0')
if redis_url and not any(redis_url.endswith(f'/{i}') for i in range(16)):
    redis_url = redis_url.rstrip('/') + '/0'

print(f"Testing Redis connection to: {redis_url}", file=sys.stderr)

# Quick Redis test without full import
try:
    import redis
    r = redis.from_url(redis_url, socket_connect_timeout=5)
    r.ping()
    print("✅ Redis connection successful!", file=sys.stderr)
    r.close()
    del r
    gc.collect()
except Exception as e:
    print(f"❌ Redis connection failed: {e}", file=sys.stderr)

# Start Celery worker with memory-optimized settings
print("=== STARTING MEMORY-OPTIMIZED CELERY WORKER ===", file=sys.stderr)

subprocess.run([
    sys.executable, "-O", "-m", "celery",
    "-A", "app.celery_app",
    "worker",
    "--loglevel=info",
    "--pool=solo",  # Single-threaded, lowest memory usage
    "--max-tasks-per-child=1",  # Restart after each task to free memory
    "--without-heartbeat",  # Disable heartbeat to save memory
    "--without-gossip",  # Disable gossip to save memory
    "--without-mingle",  # Disable synchronization on startup
])