#!/usr/bin/env python3
"""Quick status check for the backend"""

import requests
import json

BACKEND_URL = "https://codebase-scanner-backend-docker.onrender.com"

endpoints = [
    ("/", "Root"),
    ("/health", "Health"),
    ("/api/test", "API Test"),
    ("/docs", "Swagger UI"),
    ("/api/supabase/test", "Database"),
]

print("Backend Quick Status Check")
print("=" * 50)

for endpoint, name in endpoints:
    try:
        response = requests.get(f"{BACKEND_URL}{endpoint}", timeout=5)
        if response.status_code == 200:
            print(f"✅ {name}: OK")
            if endpoint == "/api/test":
                data = response.json()
                print(f"   Environment: {data.get('environment', 'Unknown')}")
        else:
            print(f"❌ {name}: Status {response.status_code}")
    except Exception as e:
        print(f"❌ {name}: {type(e).__name__}")

print("\nFor detailed testing, run:")
print("- python3 validate_deployment.py")
print("- ./test_backend.sh")