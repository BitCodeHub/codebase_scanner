#!/bin/sh
# Memory-optimized startup script for production deployment

echo "Starting Codebase Scanner Backend with memory optimizations..."

# Set memory-efficient Python garbage collection
export PYTHONGC=100,10,10

# Limit memory usage for uvicorn workers
export WEB_CONCURRENCY=1
export WORKERS=1

# Set uvicorn memory optimization flags
export UVICORN_WORKERS=1
export UVICORN_LIMIT_MAX_REQUESTS=1000
export UVICORN_LIMIT_MAX_REQUESTS_JITTER=50

# Configure memory limits for security tools
export SEMGREP_MAX_MEMORY=256
export BANDIT_MAX_MEMORY=128

# Create necessary directories if they don't exist
mkdir -p /app/logs /app/temp /app/uploads

# Log memory usage at startup
if command -v free >/dev/null 2>&1; then
    echo "Memory usage at startup:"
    free -m
fi

# Start the application with memory-optimized settings
exec uvicorn app.main:app \
    --host 0.0.0.0 \
    --port ${PORT:-8000} \
    --workers 1 \
    --loop uvloop \
    --no-access-log \
    --log-level ${LOG_LEVEL:-warning} \
    --limit-max-requests 1000 \
    --limit-max-requests-jitter 50 \
    --timeout-keep-alive 5 \
    --timeout-graceful-shutdown 10