#!/usr/bin/env python3
"""Test Redis connection directly"""
import os
import sys
import redis

redis_url = os.getenv('REDIS_URL', 'redis://localhost:6379/0')

# Ensure Redis URL has database number
if redis_url and not any(redis_url.endswith(f'/{i}') for i in range(16)):
    redis_url = redis_url.rstrip('/') + '/0'

print(f"Testing Redis connection to: {redis_url}", file=sys.stderr)

try:
    # Parse Redis URL and connect
    r = redis.from_url(redis_url)
    
    # Test connection
    r.ping()
    print("✅ Redis connection successful!", file=sys.stderr)
    
    # Set and get a test value
    r.set('test_key', 'test_value')
    value = r.get('test_key')
    print(f"✅ Redis set/get test successful: {value}", file=sys.stderr)
    
    # Clean up
    r.delete('test_key')
    
except Exception as e:
    print(f"❌ Redis connection failed: {e}", file=sys.stderr)
    sys.exit(1)