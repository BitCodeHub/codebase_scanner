#\!/usr/bin/env python3
import requests

print("🧪 Testing Simple Scanner")
print("=" * 40)

# Create test file
code = '''
# Vulnerable code
API_KEY = "sk-proj-123456789"
password = "admin123" 
AWS_SECRET = "AKIAIOSFODNN7EXAMPLE"

def sql_injection(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    
import pickle
def unsafe_load(data):
    return pickle.loads(data)
    
import hashlib
def weak_hash(pwd):
    return hashlib.md5(pwd).hexdigest()
'''

with open('vuln_test.py', 'w') as f:
    f.write(code)

# Wait for deployment
import time
print("⏳ Waiting 30s for deployment...")
time.sleep(30)

# Test simple scanner
print("\n📤 Testing simple scanner...")
with open('vuln_test.py', 'rb') as f:
    response = requests.post(
        "https://codebase-scanner-backend-docker.onrender.com/api/test/simple-scan",
        files={'file': ('vuln_test.py', f, 'text/x-python')}
    )

if response.status_code == 200:
    results = response.json()
    print(f"\n✅ SIMPLE SCANNER RESULTS:")
    print(f"   Total findings: {results['total_findings']}")
    print(f"   High severity: {results['severity_summary']['high']}")
    print(f"   Medium severity: {results['severity_summary']['medium']}")
    print(f"   AI status: {results['ai_status']}")
    print(f"\n   Sample findings:")
    for f in results['findings'][:5]:
        print(f"   - [{f['severity']}] {f['type']} at line {f['line']}")
else:
    print(f"❌ Error: {response.status_code}")
    print(response.text)

# Cleanup
import os
os.remove('vuln_test.py')

print("\n✅ Test complete\!")
