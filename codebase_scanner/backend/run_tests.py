#!/usr/bin/env python3
"""
Test runner script for the codebase scanner.
"""
import sys
import subprocess
import os

def run_tests():
    """Run all tests with coverage."""
    print("🧪 Running Codebase Scanner Tests...\n")
    
    # Set test environment
    os.environ["TESTING"] = "true"
    
    # Run pytest with coverage
    cmd = [
        "pytest",
        "-v",
        "--cov=app",
        "--cov=src",
        "--cov-report=term-missing",
        "--cov-report=html",
        "tests/"
    ]
    
    try:
        result = subprocess.run(cmd, check=True)
        print("\n✅ All tests passed!")
        print("\n📊 Coverage report generated in htmlcov/index.html")
        return 0
    except subprocess.CalledProcessError as e:
        print(f"\n❌ Tests failed with exit code {e.returncode}")
        return e.returncode
    except FileNotFoundError:
        print("❌ pytest not found. Install with: pip install pytest pytest-cov pytest-asyncio")
        return 1

def run_specific_test(test_file):
    """Run a specific test file."""
    print(f"🧪 Running tests in {test_file}...\n")
    
    cmd = ["pytest", "-v", f"tests/{test_file}"]
    
    try:
        subprocess.run(cmd, check=True)
        print(f"\n✅ Tests in {test_file} passed!")
        return 0
    except subprocess.CalledProcessError as e:
        print(f"\n❌ Tests failed with exit code {e.returncode}")
        return e.returncode

if __name__ == "__main__":
    if len(sys.argv) > 1:
        # Run specific test file
        exit_code = run_specific_test(sys.argv[1])
    else:
        # Run all tests
        exit_code = run_tests()
    
    sys.exit(exit_code)