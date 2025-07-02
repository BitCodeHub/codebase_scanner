"""
Startup warmup script to prevent cold start timeouts
"""
import asyncio
import subprocess
from typing import List
import os

async def warmup_tools():
    """Warm up all security tools on startup to prevent timeouts"""
    print("🔥 Starting container warmup...")
    
    tools = [
        ('semgrep', ['semgrep', '--version']),
        ('bandit', ['bandit', '--version']),
        ('safety', ['safety', '--version']),
        ('gitleaks', ['gitleaks', 'version']),
        ('trufflehog', ['/usr/local/bin/trufflehog', '--version']),
    ]
    
    for tool_name, command in tools:
        try:
            # Run tool check but don't wait for results
            subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            print(f"✅ Warmed up {tool_name}")
        except Exception as e:
            print(f"⚠️  Failed to warm up {tool_name}: {e}")
    
    print("🔥 Container warmup complete!")

# Run warmup on import
if os.getenv("PYTHON_ENV") == "production":
    asyncio.create_task(warmup_tools())