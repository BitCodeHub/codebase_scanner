#!/bin/sh
# Alternative startup script using Gunicorn for better memory management

echo "Starting Codebase Scanner Backend with Gunicorn..."

# Set memory-efficient Python garbage collection
export PYTHONGC=100,10,10

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

# Start with Gunicorn for better memory management
exec gunicorn app.main:app \
    --config /app/gunicorn.conf.py \
    --workers 1 \
    --max-requests 1000 \
    --max-requests-jitter 50