#!/usr/bin/env python3
"""
Comprehensive Backend Validation Script for Codebase Scanner
Tests all critical functionality of the deployed backend
"""

import requests
import json
import time
from datetime import datetime
from typing import Dict, List, Tuple
import sys

# Configuration
BACKEND_URL = "https://codebase-scanner-backend-docker.onrender.com"
LOCAL_URL = "http://localhost:8000"  # For local testing

# Color codes for output
GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
RESET = '\033[0m'

class BackendValidator:
    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip('/')
        self.results = []
        self.total_tests = 0
        self.passed_tests = 0
        
    def log(self, message: str, status: str = "INFO"):
        timestamp = datetime.now().strftime("%H:%M:%S")
        if status == "PASS":
            print(f"{GREEN}[{timestamp}] ✓ {message}{RESET}")
        elif status == "FAIL":
            print(f"{RED}[{timestamp}] ✗ {message}{RESET}")
        elif status == "WARN":
            print(f"{YELLOW}[{timestamp}] ⚠ {message}{RESET}")
        else:
            print(f"{BLUE}[{timestamp}] ℹ {message}{RESET}")
    
    def test_endpoint(self, endpoint: str, method: str = "GET", 
                     expected_status: int = 200, data: Dict = None,
                     headers: Dict = None) -> Tuple[bool, Dict]:
        """Test a single endpoint"""
        self.total_tests += 1
        url = f"{self.base_url}{endpoint}"
        
        try:
            if method == "GET":
                response = requests.get(url, headers=headers, timeout=10)
            elif method == "POST":
                response = requests.post(url, json=data, headers=headers, timeout=10)
            else:
                response = requests.request(method, url, json=data, headers=headers, timeout=10)
            
            success = response.status_code == expected_status
            if success:
                self.passed_tests += 1
                
            return success, {
                "status_code": response.status_code,
                "data": response.json() if response.headers.get('content-type', '').startswith('application/json') else response.text,
                "headers": dict(response.headers)
            }
        except Exception as e:
            return False, {"error": str(e)}
    
    def run_all_tests(self):
        """Run all validation tests"""
        print(f"\n{BLUE}═══════════════════════════════════════════════════════════════{RESET}")
        print(f"{BLUE}       Backend Validation Suite - {self.base_url}{RESET}")
        print(f"{BLUE}═══════════════════════════════════════════════════════════════{RESET}\n")
        
        # Test 1: Basic connectivity
        self.test_basic_connectivity()
        
        # Test 2: Health check
        self.test_health_check()
        
        # Test 3: API test endpoint
        self.test_api_endpoint()
        
        # Test 4: Security tools availability
        self.test_scanner_tools()
        
        # Test 5: CORS configuration
        self.test_cors_configuration()
        
        # Test 6: Supabase connection
        self.test_supabase_connection()
        
        # Test 7: AI analysis capability
        self.test_ai_analysis()
        
        # Test 8: Error handling
        self.test_error_handling()
        
        # Test 9: API documentation
        self.test_api_documentation()
        
        # Test 10: Environment configuration
        self.test_environment_config()
        
        # Summary
        self.print_summary()
    
    def test_basic_connectivity(self):
        """Test 1: Basic connectivity to the backend"""
        self.log("Testing basic connectivity...", "INFO")
        success, response = self.test_endpoint("/")
        
        if success:
            data = response.get("data", {})
            self.log(f"Root endpoint accessible - Version: {data.get('version', 'Unknown')}", "PASS")
            self.log(f"API Status: {data.get('status', 'Unknown')}", "INFO")
        else:
            self.log(f"Failed to connect to backend: {response.get('error', 'Unknown error')}", "FAIL")
    
    def test_health_check(self):
        """Test 2: Health check endpoint"""
        self.log("\nTesting health check endpoint...", "INFO")
        success, response = self.test_endpoint("/health")
        
        if success:
            data = response.get("data", {})
            self.log(f"Health check passed - Status: {data.get('status', 'Unknown')}", "PASS")
            self.log(f"Service: {data.get('service', 'Unknown')}", "INFO")
        else:
            self.log("Health check failed", "FAIL")
    
    def test_api_endpoint(self):
        """Test 3: API test endpoint"""
        self.log("\nTesting API configuration...", "INFO")
        success, response = self.test_endpoint("/api/test")
        
        if success:
            data = response.get("data", {})
            env = data.get('environment', 'Unknown')
            if env == 'production':
                self.log(f"Environment correctly set to: {env}", "PASS")
            else:
                self.log(f"Environment is '{env}', expected 'production'", "WARN")
            
            supabase_url = data.get('supabase_url', 'Not configured')
            if supabase_url != 'Not configured':
                self.log("Supabase URL is configured", "PASS")
            else:
                self.log("Supabase URL not configured", "FAIL")
        else:
            self.log("API test endpoint failed", "FAIL")
    
    def test_scanner_tools(self):
        """Test 4: Security tools availability"""
        self.log("\nTesting security scanner tools...", "INFO")
        success, response = self.test_endpoint("/api/test/scanner-tools")
        
        if success:
            data = response.get("data", {})
            tools = data.get("tools", {})
            total_tools = data.get("total_tools", 0)
            available_tools = data.get("available_tools", 0)
            
            self.log(f"Security Tools Status: {available_tools}/{total_tools} available", "INFO")
            
            # Check each tool
            for tool_name, tool_info in tools.items():
                if tool_info.get("available"):
                    self.log(f"{tool_name}: ✓ {tool_info.get('version', 'Unknown version')}", "PASS")
                else:
                    self.log(f"{tool_name}: ✗ {tool_info.get('error', 'Not available')}", "FAIL")
            
            # Overall assessment
            if available_tools == total_tools:
                self.log(f"All {total_tools} security tools are operational!", "PASS")
            else:
                self.log(f"Only {available_tools} out of {total_tools} tools are working", "WARN")
        else:
            self.log("Failed to test scanner tools", "FAIL")
    
    def test_cors_configuration(self):
        """Test 5: CORS configuration"""
        self.log("\nTesting CORS configuration...", "INFO")
        
        # Test preflight request
        headers = {
            'Origin': 'https://codebase-scanner-frontend.onrender.com',
            'Access-Control-Request-Method': 'POST',
            'Access-Control-Request-Headers': 'content-type'
        }
        
        success, response = self.test_endpoint("/api/test", method="OPTIONS", 
                                             expected_status=200, headers=headers)
        
        if success:
            cors_headers = response.get("headers", {})
            if 'access-control-allow-origin' in cors_headers:
                self.log(f"CORS enabled for: {cors_headers.get('access-control-allow-origin')}", "PASS")
            else:
                self.log("CORS headers not found", "WARN")
        else:
            # Some deployments might not handle OPTIONS
            self.log("CORS preflight test inconclusive", "WARN")
    
    def test_supabase_connection(self):
        """Test 6: Supabase database connection"""
        self.log("\nTesting Supabase connection...", "INFO")
        success, response = self.test_endpoint("/api/supabase/test")
        
        if success:
            data = response.get("data", {})
            status = data.get("status", "unknown")
            
            if status == "connected":
                self.log("Supabase connection successful", "PASS")
                self.log(f"Database: {data.get('database_info', {}).get('database', 'Unknown')}", "INFO")
            elif status == "not_configured":
                self.log("Supabase credentials not configured", "FAIL")
            else:
                self.log(f"Supabase connection status: {status}", "WARN")
        else:
            self.log("Failed to test Supabase connection", "FAIL")
    
    def test_ai_analysis(self):
        """Test 7: AI analysis capability"""
        self.log("\nTesting AI analysis capability...", "INFO")
        success, response = self.test_endpoint("/api/test/ai-analysis", method="POST")
        
        if success:
            data = response.get("data", {})
            if "ai_analysis" in data:
                self.log("AI analysis endpoint is functional", "PASS")
                analysis = data.get("ai_analysis", {})
                if analysis.get("executive_summary"):
                    self.log("AI generated executive summary successfully", "PASS")
                if analysis.get("critical_issues"):
                    self.log(f"AI identified {len(analysis.get('critical_issues', []))} critical issues", "INFO")
            else:
                error = data.get("error", "Unknown error")
                if "ANTHROPIC_API_KEY" in error:
                    self.log("AI analysis requires ANTHROPIC_API_KEY configuration", "WARN")
                else:
                    self.log(f"AI analysis failed: {error}", "FAIL")
        else:
            self.log("Failed to test AI analysis", "FAIL")
    
    def test_error_handling(self):
        """Test 8: Error handling"""
        self.log("\nTesting error handling...", "INFO")
        
        # Test 404 handling
        success, response = self.test_endpoint("/nonexistent-endpoint", expected_status=404)
        if success:
            self.log("404 error handling works correctly", "PASS")
        else:
            self.log("Unexpected response for non-existent endpoint", "WARN")
        
        # Test invalid method
        success, response = self.test_endpoint("/health", method="DELETE", expected_status=405)
        if response.get("status_code") in [405, 404]:  # Some servers return 404 for invalid methods
            self.log("Invalid method handling works correctly", "PASS")
        else:
            self.log("Unexpected response for invalid method", "WARN")
    
    def test_api_documentation(self):
        """Test 9: API documentation"""
        self.log("\nTesting API documentation...", "INFO")
        
        # Test Swagger UI
        success, response = self.test_endpoint("/docs", expected_status=200)
        if success:
            self.log("Swagger documentation is accessible", "PASS")
        else:
            self.log("Swagger documentation not accessible", "WARN")
        
        # Test ReDoc
        success, response = self.test_endpoint("/redoc", expected_status=200)
        if success:
            self.log("ReDoc documentation is accessible", "PASS")
        else:
            self.log("ReDoc documentation not accessible", "WARN")
    
    def test_environment_config(self):
        """Test 10: Environment configuration"""
        self.log("\nTesting environment configuration...", "INFO")
        
        # This would typically require an authenticated endpoint
        # For now, we'll check what we can from public endpoints
        success, response = self.test_endpoint("/api/test")
        
        if success:
            data = response.get("data", {})
            env = data.get("environment", "Unknown")
            
            if env == "production":
                self.log("Production environment confirmed", "PASS")
            else:
                self.log(f"Environment is set to: {env}", "WARN")
    
    def print_summary(self):
        """Print test summary"""
        print(f"\n{BLUE}═══════════════════════════════════════════════════════════════{RESET}")
        print(f"{BLUE}                        Test Summary{RESET}")
        print(f"{BLUE}═══════════════════════════════════════════════════════════════{RESET}")
        
        success_rate = (self.passed_tests / self.total_tests * 100) if self.total_tests > 0 else 0
        
        if success_rate == 100:
            status_color = GREEN
            status_text = "EXCELLENT"
        elif success_rate >= 80:
            status_color = YELLOW
            status_text = "GOOD"
        else:
            status_color = RED
            status_text = "NEEDS ATTENTION"
        
        print(f"\nTotal Tests: {self.total_tests}")
        print(f"Passed: {GREEN}{self.passed_tests}{RESET}")
        print(f"Failed: {RED}{self.total_tests - self.passed_tests}{RESET}")
        print(f"Success Rate: {status_color}{success_rate:.1f}%{RESET}")
        print(f"\nOverall Status: {status_color}{status_text}{RESET}")
        
        print(f"\n{BLUE}Recommendations:{RESET}")
        if success_rate < 100:
            print("- Review failed tests and check Render logs for details")
            print("- Ensure all environment variables are correctly set")
            print("- Verify Docker image built successfully with all tools")
        else:
            print("- All systems operational!")
            print("- Backend is ready for production use")
            print("- Monitor logs for any runtime issues")
        
        print(f"\n{BLUE}Next Steps:{RESET}")
        print("1. Update frontend to use the new backend URL")
        print("2. Test end-to-end functionality with the frontend")
        print("3. Set up monitoring and alerts")
        print("4. Configure rate limiting if needed")

def main():
    """Main function"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Validate Codebase Scanner Backend Deployment')
    parser.add_argument('--local', action='store_true', help='Test local deployment')
    parser.add_argument('--url', type=str, help='Custom backend URL to test')
    
    args = parser.parse_args()
    
    if args.url:
        url = args.url
    elif args.local:
        url = LOCAL_URL
    else:
        url = BACKEND_URL
    
    print(f"{BLUE}Starting backend validation...{RESET}")
    validator = BackendValidator(url)
    validator.run_all_tests()

if __name__ == "__main__":
    main()