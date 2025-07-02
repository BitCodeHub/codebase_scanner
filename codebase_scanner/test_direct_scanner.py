#!/usr/bin/env python3
"""
Direct test of scanner tools locally
"""

import subprocess
import json
import tempfile
import os

def test_scanners_directly():
    print("🧪 Testing Scanner Tools Directly")
    print("=" * 60)
    
    # Create test file with vulnerabilities
    test_code = '''
import os
API_KEY = "sk-1234567890abcdef"
password = "admin123"
AWS_SECRET = "AKIAIOSFODNN7EXAMPLE"

def unsafe_query(user_input):
    query = f"SELECT * FROM users WHERE id = {user_input}"
    return query

def weak_hash(password):
    import hashlib
    return hashlib.md5(password.encode()).hexdigest()
'''
    
    # Save to temp file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write(test_code)
        test_file = f.name
    
    print(f"📝 Created test file: {test_file}")
    
    # Test 1: Bandit
    print("\n1️⃣ Testing Bandit...")
    try:
        result = subprocess.run(
            ["bandit", "-r", test_file, "-f", "json"],
            capture_output=True,
            text=True
        )
        if result.stdout:
            data = json.loads(result.stdout)
            issues = data.get('results', [])
            print(f"   ✅ Bandit found {len(issues)} issues")
            for issue in issues[:3]:
                print(f"   - {issue['issue_text']}")
        else:
            print("   ❌ No output from Bandit")
    except Exception as e:
        print(f"   ❌ Bandit error: {e}")
    
    # Test 2: Semgrep
    print("\n2️⃣ Testing Semgrep...")
    try:
        result = subprocess.run(
            ["semgrep", "--config=auto", "--json", test_file],
            capture_output=True,
            text=True
        )
        if result.stdout:
            data = json.loads(result.stdout)
            results = data.get('results', [])
            print(f"   ✅ Semgrep found {len(results)} issues")
            for r in results[:3]:
                print(f"   - {r.get('extra', {}).get('message', 'Unknown')}")
        else:
            print("   ❌ No output from Semgrep")
    except Exception as e:
        print(f"   ❌ Semgrep error: {e}")
    
    # Test 3: Gitleaks
    print("\n3️⃣ Testing Gitleaks...")
    try:
        # Create temp directory
        temp_dir = tempfile.mkdtemp()
        temp_file = os.path.join(temp_dir, "test.py")
        with open(temp_file, 'w') as f:
            f.write(test_code)
        
        result = subprocess.run(
            ["gitleaks", "detect", "--source", temp_dir, "--no-git", "-v"],
            capture_output=True,
            text=True
        )
        if "leaks found" in result.stderr or "leaks found" in result.stdout:
            print("   ✅ Gitleaks found secrets")
            print(f"   Output: {result.stderr[:200]}")
        else:
            print("   ❌ Gitleaks found no secrets")
            print(f"   stdout: {result.stdout[:100]}")
            print(f"   stderr: {result.stderr[:100]}")
    except Exception as e:
        print(f"   ❌ Gitleaks error: {e}")
    
    # Cleanup
    os.unlink(test_file)
    print("\n✅ Test complete")

if __name__ == "__main__":
    test_scanners_directly()