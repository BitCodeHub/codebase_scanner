import requests
import os

# Simple test to verify scanner is working
response = requests.get("https://codebase-scanner-backend-docker.onrender.com/api/test/scanner-tools-cached")
print("Scanner tools status:")
print(response.json()['summary'])

# Create a test file with obvious issues
test_code = """
API_KEY = "sk-1234567890"
password = "admin123"
"""

# Upload the file
files = {'file': ('test.py', test_code.encode(), 'text/x-python')}
data = {'enable_ai_analysis': 'false', 'scan_type': 'comprehensive'}

print("\nUploading test file...")
response = requests.post(
    "https://codebase-scanner-backend-docker.onrender.com/api/scans/upload-universal",
    files=files,
    data=data
)

if response.status_code == 200:
    scan_id = response.json()['scan_id']
    print(f"Scan ID: {scan_id}")
    
    # Wait and check results
    import time
    time.sleep(10)
    
    results = requests.get(
        f"https://codebase-scanner-backend-docker.onrender.com/api/scans/upload-universal/{scan_id}/results"
    ).json()
    
    print("\nScan results:")
    print(f"Status: {results['status']}")
    print(f"Files scanned: {results['files_scanned']}")
    print(f"Total findings: {results['total_findings']}")
    print(f"Secrets found: {results['secrets']['secrets_found']}")
else:
    print(f"Upload failed: {response.status_code}")
    print(response.text)
