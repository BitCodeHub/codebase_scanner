#!/usr/bin/env python3
"""
Test comprehensive scanner with limited tools for demonstration
"""

import asyncio
import sys
import json
from pathlib import Path
from comprehensive_scanner import ComprehensiveScanner, SecurityTool

class TestScanner(ComprehensiveScanner):
    """Test scanner with limited tools for faster execution"""
    
    def get_all_security_tools(self):
        """Return only core tools for testing"""
        return [
            SecurityTool(
                name="semgrep",
                command=["semgrep", "--config=auto", "--json", "--output={output}", "--max-target-bytes=10000000"],
                output_format="json",
                description="Static analysis with security rules",
                timeout=60
            ),
            SecurityTool(
                name="gitleaks",
                command=["gitleaks", "detect", "--source=.", "--report-format=json", "--report-path={output}", "--no-git"],
                output_format="json",
                description="Git secrets scanner",
                timeout=60
            ),
            SecurityTool(
                name="bandit",
                command=["bandit", "-r", ".", "-f", "json", "-o", "{output}", "--skip", "B101,B601"],
                output_format="json",
                description="Python security linter",
                timeout=60
            ),
            SecurityTool(
                name="detect-secrets",
                command=["detect-secrets", "scan", "--all-files", ".", ">", "{output}"],
                output_format="json",
                description="Advanced credential scanning",
                timeout=60
            )
        ]

async def main():
    if len(sys.argv) < 2:
        print("Usage: python test_comprehensive_scan.py <repository_path>")
        sys.exit(1)
        
    repo_path = sys.argv[1]
    scanner = TestScanner(repo_path)
    
    print(f"[*] Running limited comprehensive scan on {repo_path}")
    print(f"[*] Using 4 core security tools for demonstration")
    
    # Run scan
    results = await scanner.scan_repository()
    
    # Generate report
    report_path = scanner.generate_enterprise_report(results)
    
    print(f"\n[✓] Scan complete!")
    print(f"[✓] Total vulnerabilities found: {results['metrics']['total_vulnerabilities']}")
    print(f"[✓] Critical: {results['metrics']['critical_count']}")
    print(f"[✓] High: {results['metrics']['high_count']}")
    print(f"[✓] Report generated: {report_path}")
    
    # Show sample findings
    if results['vulnerabilities']:
        print("\n[*] Sample findings:")
        for vuln in results['vulnerabilities'][:5]:
            print(f"  - {vuln['severity']}: {vuln['title']} in {vuln.get('file_path', 'N/A')}")

if __name__ == "__main__":
    asyncio.run(main())