#!/bin/bash

echo "🚀 Deploying Codebase Scanner Backend..."

# Verify environment
echo "📍 Environment: ${PYTHON_ENV:-development}"
echo "📍 Workers: ${WORKERS:-4}"
echo "📍 Log Level: ${LOG_LEVEL:-info}"

# Verify tools installation
if [ -f "/app/verify_tools.sh" ]; then
    echo "📦 Verifying security tools..."
    /app/verify_tools.sh
else
    echo "⚠️  Tool verification script not found"
fi

# Create required directories
echo "📁 Creating required directories..."
mkdir -p /app/logs /app/temp /app/uploads 2>/dev/null || true

# Check database connection
echo "🗄️ Checking database connection..."
python -c "
import os
try:
    from supabase import create_client
    url = os.getenv('SUPABASE_URL')
    key = os.getenv('SUPABASE_SERVICE_KEY')
    if url and key:
        client = create_client(url, key)
        print('✅ Database connection successful')
    else:
        print('⚠️  Database credentials not configured')
except Exception as e:
    print(f'❌ Database connection failed: {e}')
" || true

# Start the application
echo "🎯 Starting application..."
exec uvicorn app.main:app \
    --host 0.0.0.0 \
    --port ${PORT:-8000} \
    --workers ${WORKERS:-4} \
    --log-level ${LOG_LEVEL:-info}