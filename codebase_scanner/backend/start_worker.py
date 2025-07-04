#!/usr/bin/env python3
"""Start Celery worker with proper configuration"""
import os
import sys
import subprocess
import redis

# Debug information
print("=== WORKER STARTUP DEBUG ===", file=sys.stderr)
print(f"Current directory: {os.getcwd()}", file=sys.stderr)
print(f"REDIS_URL from env: {os.getenv('REDIS_URL', 'NOT SET')}", file=sys.stderr)
print(f"Directory contents: {os.listdir('.')}", file=sys.stderr)

# Test Redis connection first
redis_url = os.getenv('REDIS_URL', 'redis://localhost:6379/0')
if redis_url and not any(redis_url.endswith(f'/{i}') for i in range(16)):
    redis_url = redis_url.rstrip('/') + '/0'

print(f"Testing Redis connection to: {redis_url}", file=sys.stderr)
try:
    r = redis.from_url(redis_url)
    r.ping()
    print("✅ Redis connection test successful!", file=sys.stderr)
except Exception as e:
    print(f"❌ Redis connection test failed: {e}", file=sys.stderr)

# Add current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import and test Redis URL
try:
    from app.celery_app import celery_app
    print(f"Celery broker URL: {celery_app.conf.broker_url}", file=sys.stderr)
    print(f"Celery backend URL: {celery_app.conf.result_backend}", file=sys.stderr)
except Exception as e:
    print(f"Error importing celery_app: {e}", file=sys.stderr)

print("=== STARTING CELERY WORKER ===", file=sys.stderr)

# Start Celery worker
subprocess.run([
    sys.executable, "-m", "celery",
    "-A", "app.celery_app",
    "worker",
    "--loglevel=info"
])