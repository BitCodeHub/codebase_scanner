#!/usr/bin/env python3
"""Debug script to understand Render environment"""
import os
import sys

print("=== DEBUG ENVIRONMENT ===", file=sys.stderr)
print(f"Current working directory: {os.getcwd()}", file=sys.stderr)
print(f"Directory contents: {os.listdir('.')}", file=sys.stderr)
print(f"Python path: {sys.path}", file=sys.stderr)
print(f"REDIS_URL: {os.getenv('REDIS_URL', 'NOT SET')}", file=sys.stderr)
print(f"RENDER: {os.getenv('RENDER', 'NOT SET')}", file=sys.stderr)
print(f"All env vars with REDIS: {[k for k in os.environ.keys() if 'REDIS' in k]}", file=sys.stderr)

# Try to import celery_app
try:
    from app.celery_app import celery_app
    print(f"Successfully imported celery_app", file=sys.stderr)
    print(f"Celery broker: {celery_app.conf.broker_url}", file=sys.stderr)
except Exception as e:
    print(f"Failed to import celery_app: {e}", file=sys.stderr)

print("=== END DEBUG ===", file=sys.stderr)