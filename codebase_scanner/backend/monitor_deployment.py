#!/usr/bin/env python3
"""
Monitor Backend Deployment Status
Continuously checks if the backend is up and running
"""

import requests
import time
from datetime import datetime
import sys

# Configuration
BACKEND_URL = "https://codebase-scanner-backend-docker.onrender.com"
CHECK_INTERVAL = 10  # seconds
MAX_ATTEMPTS = 60  # 10 minutes total

# Color codes
GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
RESET = '\033[0m'

def check_backend_status(url):
    """Check if backend is responding"""
    try:
        response = requests.get(f"{url}/health", timeout=5)
        return response.status_code == 200, response.status_code
    except requests.exceptions.RequestException as e:
        return False, str(e)

def monitor_deployment():
    """Monitor deployment until it's ready"""
    print(f"{BLUE}Monitoring Backend Deployment...{RESET}")
    print(f"URL: {BACKEND_URL}")
    print(f"Checking every {CHECK_INTERVAL} seconds\n")
    
    attempts = 0
    last_status = None
    
    while attempts < MAX_ATTEMPTS:
        attempts += 1
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        is_up, status = check_backend_status(BACKEND_URL)
        
        status_str = f"Status: {status}"
        if status != last_status:
            if is_up:
                print(f"{GREEN}[{timestamp}] ✓ Backend is UP! {status_str}{RESET}")
                break
            else:
                print(f"{RED}[{timestamp}] ✗ Backend is DOWN. {status_str}{RESET}")
            last_status = status
        else:
            print(f"{YELLOW}[{timestamp}] ... Still waiting (attempt {attempts}/{MAX_ATTEMPTS}){RESET}")
        
        if not is_up and attempts < MAX_ATTEMPTS:
            time.sleep(CHECK_INTERVAL)
    
    if is_up:
        print(f"\n{GREEN}Backend is ready!{RESET}")
        print(f"Visit: {BACKEND_URL}")
        print(f"API Docs: {BACKEND_URL}/docs")
        
        # Quick health check
        try:
            response = requests.get(f"{BACKEND_URL}/api/test", timeout=5)
            data = response.json()
            env = data.get('environment', 'Unknown')
            print(f"\nEnvironment: {env}")
            
            # Check tools
            tools_response = requests.get(f"{BACKEND_URL}/api/test/scanner-tools", timeout=10)
            if tools_response.status_code == 200:
                tools_data = tools_response.json()
                available = tools_data.get('available_tools', 0)
                total = tools_data.get('total_tools', 0)
                print(f"Security Tools: {available}/{total} available")
        except:
            pass
            
        return True
    else:
        print(f"\n{RED}Backend did not come up after {MAX_ATTEMPTS * CHECK_INTERVAL} seconds{RESET}")
        print("\nTroubleshooting steps:")
        print("1. Check Render dashboard for deployment logs")
        print("2. Look for build errors or runtime issues")
        print("3. Verify all environment variables are set correctly")
        print("4. Check if the Docker image built successfully")
        return False

if __name__ == "__main__":
    success = monitor_deployment()
    sys.exit(0 if success else 1)