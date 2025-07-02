#!/usr/bin/env python3
"""
Comprehensive Security Analysis of Hyundai Kia Connect API
"""

import os
import subprocess
import json
import re
from datetime import datetime
from pathlib import Path

class SecurityAnalyzer:
    def __init__(self, repo_path):
        self.repo_path = Path(repo_path)
        self.results = {
            "repository": "hyundai_kia_connect_api",
            "scan_date": datetime.now().isoformat(),
            "findings": [],
            "summary": {
                "total_findings": 0,
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "info": 0
            },
            "code_analysis": {},
            "security_issues": [],
            "recommendations": []
        }
    
    def run_bandit(self):
        """Run Bandit for Python security analysis"""
        print("\n🔍 Running Bandit Security Analysis...")
        try:
            result = subprocess.run(
                ["bandit", "-r", str(self.repo_path), "-f", "json"],
                capture_output=True,
                text=True
            )
            if result.returncode == 0 or result.stdout:
                bandit_results = json.loads(result.stdout)
                for issue in bandit_results.get("results", []):
                    self.results["findings"].append({
                        "tool": "Bandit",
                        "severity": issue["issue_severity"],
                        "confidence": issue["issue_confidence"],
                        "title": issue["issue_text"],
                        "file": issue["filename"],
                        "line": issue["line_number"],
                        "test_id": issue["test_id"],
                        "test_name": issue["test_name"]
                    })
                print(f"  ✅ Found {len(bandit_results.get('results', []))} issues")
        except Exception as e:
            print(f"  ❌ Bandit failed: {e}")
    
    def run_safety(self):
        """Check for known vulnerabilities in dependencies"""
        print("\n🔍 Running Safety Check...")
        try:
            # First, check if requirements.txt exists
            req_file = self.repo_path / "requirements.txt"
            if req_file.exists():
                result = subprocess.run(
                    ["safety", "check", "-r", str(req_file), "--json"],
                    capture_output=True,
                    text=True
                )
                if result.stdout:
                    safety_results = json.loads(result.stdout)
                    for vuln in safety_results:
                        self.results["findings"].append({
                            "tool": "Safety",
                            "severity": "high",
                            "title": f"Vulnerable dependency: {vuln.get('package')}",
                            "description": vuln.get("vulnerability", ""),
                            "affected_version": vuln.get("affected_versions", ""),
                            "safe_version": vuln.get("more_info_url", "")
                        })
                    print(f"  ✅ Found {len(safety_results)} vulnerable dependencies")
            else:
                print("  ⚠️  No requirements.txt found")
        except Exception as e:
            print(f"  ❌ Safety check failed: {e}")
    
    def analyze_code_patterns(self):
        """Analyze code for security patterns"""
        print("\n🔍 Analyzing Code Patterns...")
        
        security_patterns = {
            "hardcoded_secrets": [
                r'(?i)(api[_-]?key|apikey|secret[_-]?key|password|passwd|pwd)\s*=\s*["\'][\w-]+["\']',
                r'(?i)(token|auth|bearer)\s*=\s*["\'][\w-]+["\']'
            ],
            "hardcoded_urls": [
                r'https?://[\w\.-]+\.(hyundai|kia|bluelink)[\w\.-]*',
            ],
            "unsafe_ssl": [
                r'verify\s*=\s*False',
                r'ssl\.SSLContext\(\)',
                r'urllib\.request\.urlopen\([^)]*\)'
            ],
            "sensitive_data_logging": [
                r'print\s*\(.*(?:password|token|secret|key)',
                r'logging\.(?:debug|info)\s*\(.*(?:password|token|secret|key)'
            ],
            "unsafe_pickle": [
                r'pickle\.loads?\(',
                r'cPickle\.loads?\('
            ],
            "exec_eval": [
                r'\beval\s*\(',
                r'\bexec\s*\(',
                r'subprocess\.(?:call|run|Popen)\s*\([^,]*shell\s*=\s*True'
            ]
        }
        
        issues_found = {}
        
        for root, _, files in os.walk(self.repo_path):
            for file in files:
                if file.endswith('.py'):
                    file_path = Path(root) / file
                    try:
                        with open(file_path, 'r', encoding='utf-8') as f:
                            content = f.read()
                            
                        for pattern_type, patterns in security_patterns.items():
                            for pattern in patterns:
                                matches = re.finditer(pattern, content)
                                for match in matches:
                                    line_no = content[:match.start()].count('\n') + 1
                                    if pattern_type not in issues_found:
                                        issues_found[pattern_type] = []
                                    
                                    issues_found[pattern_type].append({
                                        "file": str(file_path.relative_to(self.repo_path)),
                                        "line": line_no,
                                        "match": match.group(0)[:100]
                                    })
                    except Exception as e:
                        print(f"  ⚠️  Error reading {file_path}: {e}")
        
        # Add findings
        for issue_type, occurrences in issues_found.items():
            if occurrences:
                severity = "high" if issue_type in ["hardcoded_secrets", "exec_eval"] else "medium"
                self.results["findings"].append({
                    "tool": "Pattern Analysis",
                    "severity": severity,
                    "title": f"Potential {issue_type.replace('_', ' ')} detected",
                    "description": f"Found {len(occurrences)} instances",
                    "occurrences": occurrences[:5]  # Limit to first 5
                })
        
        print(f"  ✅ Analyzed {len(issues_found)} security patterns")
    
    def analyze_api_security(self):
        """Analyze API-specific security concerns"""
        print("\n🔍 Analyzing API Security...")
        
        api_files = list(self.repo_path.glob("**/*Api*.py"))
        api_files.extend(list(self.repo_path.glob("**/bluelink.py")))
        
        api_security_issues = []
        
        for api_file in api_files:
            try:
                with open(api_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                # Check for authentication handling
                if 'login' in content.lower() or 'authenticate' in content.lower():
                    # Check if passwords are stored or logged
                    if re.search(r'self\.password\s*=', content):
                        api_security_issues.append({
                            "file": str(api_file.relative_to(self.repo_path)),
                            "issue": "Password stored in instance variable",
                            "severity": "high",
                            "recommendation": "Use secure token storage instead of storing passwords"
                        })
                
                # Check for proper error handling
                if 'except' in content and 'pass' in content:
                    if re.search(r'except.*:\s*pass', content):
                        api_security_issues.append({
                            "file": str(api_file.relative_to(self.repo_path)),
                            "issue": "Silent exception handling",
                            "severity": "medium",
                            "recommendation": "Log exceptions properly for security monitoring"
                        })
                
                # Check for rate limiting
                if 'time.sleep' not in content and 'ratelimit' not in content.lower():
                    api_security_issues.append({
                        "file": str(api_file.relative_to(self.repo_path)),
                        "issue": "No rate limiting detected",
                        "severity": "medium",
                        "recommendation": "Implement rate limiting to prevent API abuse"
                    })
                    
            except Exception as e:
                print(f"  ⚠️  Error analyzing {api_file}: {e}")
        
        self.results["security_issues"].extend(api_security_issues)
        print(f"  ✅ Found {len(api_security_issues)} API security issues")
    
    def analyze_authentication(self):
        """Analyze authentication mechanisms"""
        print("\n🔍 Analyzing Authentication...")
        
        auth_issues = []
        
        # Look for authentication-related files
        for root, _, files in os.walk(self.repo_path):
            for file in files:
                if file.endswith('.py'):
                    file_path = Path(root) / file
                    try:
                        with open(file_path, 'r', encoding='utf-8') as f:
                            content = f.read()
                        
                        # Check for JWT handling
                        if 'jwt' in content.lower() or 'token' in content.lower():
                            if not re.search(r'verify.*=.*True', content):
                                auth_issues.append({
                                    "file": str(file_path.relative_to(self.repo_path)),
                                    "issue": "JWT token verification might be missing",
                                    "severity": "high"
                                })
                        
                        # Check for session management
                        if 'session' in content.lower():
                            if not re.search(r'session.*timeout|expire', content.lower()):
                                auth_issues.append({
                                    "file": str(file_path.relative_to(self.repo_path)),
                                    "issue": "No session timeout detected",
                                    "severity": "medium"
                                })
                                
                    except Exception as e:
                        pass
        
        self.results["security_issues"].extend(auth_issues)
        print(f"  ✅ Found {len(auth_issues)} authentication issues")
    
    def generate_report(self):
        """Generate comprehensive security report"""
        print("\n📊 Generating Security Report...")
        
        # Update summary
        for finding in self.results["findings"]:
            severity = finding.get("severity", "info").lower()
            if severity in self.results["summary"]:
                self.results["summary"][severity] += 1
            self.results["summary"]["total_findings"] += 1
        
        # Add recommendations
        if self.results["summary"]["critical"] > 0 or self.results["summary"]["high"] > 0:
            self.results["recommendations"].append(
                "URGENT: Address critical and high severity issues immediately"
            )
        
        if any("hardcoded" in str(f) for f in self.results["findings"]):
            self.results["recommendations"].append(
                "Move all hardcoded credentials to environment variables"
            )
        
        if any("ssl" in str(f).lower() for f in self.results["findings"]):
            self.results["recommendations"].append(
                "Ensure all SSL/TLS connections use proper certificate verification"
            )
        
        self.results["recommendations"].extend([
            "Implement comprehensive logging for security events",
            "Add rate limiting to prevent API abuse",
            "Use secure token storage mechanisms",
            "Implement proper session management with timeouts",
            "Add input validation for all user inputs",
            "Review and update dependencies regularly"
        ])
        
        return self.results
    
    def save_report(self):
        """Save report to file"""
        report_file = f"hyundai_api_security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(report_file, 'w') as f:
            json.dump(self.results, f, indent=2)
        
        # Also create a readable report
        readable_report = f"hyundai_api_security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        with open(readable_report, 'w') as f:
            f.write("=" * 80 + "\n")
            f.write("HYUNDAI KIA CONNECT API - SECURITY ANALYSIS REPORT\n")
            f.write("=" * 80 + "\n\n")
            
            f.write(f"Scan Date: {self.results['scan_date']}\n")
            f.write(f"Repository: {self.results['repository']}\n\n")
            
            f.write("SUMMARY\n")
            f.write("-" * 40 + "\n")
            f.write(f"Total Findings: {self.results['summary']['total_findings']}\n")
            f.write(f"Critical: {self.results['summary']['critical']}\n")
            f.write(f"High: {self.results['summary']['high']}\n")
            f.write(f"Medium: {self.results['summary']['medium']}\n")
            f.write(f"Low: {self.results['summary']['low']}\n")
            f.write(f"Info: {self.results['summary']['info']}\n\n")
            
            f.write("TOP SECURITY ISSUES\n")
            f.write("-" * 40 + "\n")
            for issue in self.results['security_issues'][:10]:
                f.write(f"\n[{issue.get('severity', 'info').upper()}] {issue.get('issue', 'Unknown')}\n")
                f.write(f"File: {issue.get('file', 'Unknown')}\n")
                if 'recommendation' in issue:
                    f.write(f"Recommendation: {issue['recommendation']}\n")
            
            f.write("\n\nRECOMMENDATIONS\n")
            f.write("-" * 40 + "\n")
            for i, rec in enumerate(self.results['recommendations'], 1):
                f.write(f"{i}. {rec}\n")
        
        print(f"\n✅ Reports saved:")
        print(f"  - JSON: {report_file}")
        print(f"  - Text: {readable_report}")
        
        return report_file, readable_report

def main():
    print("🚀 Starting Comprehensive Security Analysis")
    print("=" * 80)
    
    repo_path = Path("hyundai_kia_connect_api")
    analyzer = SecurityAnalyzer(repo_path)
    
    # Run all analyses
    analyzer.run_bandit()
    analyzer.run_safety()
    analyzer.analyze_code_patterns()
    analyzer.analyze_api_security()
    analyzer.analyze_authentication()
    
    # Generate and save report
    report = analyzer.generate_report()
    json_file, text_file = analyzer.save_report()
    
    # Print summary
    print("\n" + "=" * 80)
    print("ANALYSIS COMPLETE")
    print("=" * 80)
    print(f"\nTotal Security Findings: {report['summary']['total_findings']}")
    print(f"Critical Issues: {report['summary']['critical']}")
    print(f"High Severity: {report['summary']['high']}")
    print(f"Medium Severity: {report['summary']['medium']}")
    print(f"Low Severity: {report['summary']['low']}")
    
    if report['summary']['critical'] > 0 or report['summary']['high'] > 0:
        print("\n⚠️  URGENT: Critical or high severity issues found!")
        print("Please review the reports immediately.")

if __name__ == "__main__":
    main()