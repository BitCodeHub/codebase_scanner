#!/usr/bin/env python3
"""
Comprehensive Security Scanner Orchestrator
Ensures all available security tools are used and generates consistent enterprise reports
"""

import json
import subprocess
import os
import asyncio
from datetime import datetime
from typing import Dict, List, Any, Optional
from pathlib import Path
import tempfile
import shutil
from dataclasses import dataclass
from enum import Enum
import hashlib
import re


class SeverityLevel(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class SecurityTool:
    name: str
    command: List[str]
    output_format: str
    enabled: bool = True
    timeout: int = 300
    description: str = ""
    

@dataclass
class Vulnerability:
    tool: str
    severity: SeverityLevel
    title: str
    description: str
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    cwe: Optional[str] = None
    owasp: Optional[str] = None
    remediation: Optional[str] = None
    confidence: str = "HIGH"
    

class ComprehensiveScanner:
    """Orchestrates all security scanning tools and generates comprehensive reports"""
    
    def __init__(self, repo_path: str):
        self.repo_path = Path(repo_path)
        self.scan_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.results_dir = self.repo_path / "scan-results" / self.scan_id
        self.results_dir.mkdir(parents=True, exist_ok=True)
        self.vulnerabilities: List[Vulnerability] = []
        self.metrics = {
            "start_time": datetime.now(),
            "end_time": None,
            "tools_run": 0,
            "tools_failed": 0,
            "files_scanned": 0,
            "lines_scanned": 0
        }
        
    def get_all_security_tools(self) -> List[SecurityTool]:
        """Define all available security scanning tools"""
        return [
            # Core Security Scanners (10 tools as per CLAUDE.md)
            SecurityTool(
                name="semgrep",
                command=["semgrep", "--config=auto", "--json", "--output={output}"],
                output_format="json",
                description="Static analysis with security rules"
            ),
            SecurityTool(
                name="bandit",
                command=["bandit", "-r", ".", "-f", "json", "-o", "{output}"],
                output_format="json",
                description="Python security linter"
            ),
            SecurityTool(
                name="safety",
                command=["safety", "check", "--json", "--output", "{output}"],
                output_format="json",
                description="Python dependency vulnerability scanner"
            ),
            SecurityTool(
                name="gitleaks",
                command=["gitleaks", "detect", "--source=.", "--report-format=json", "--report-path={output}"],
                output_format="json",
                description="Git secrets scanner"
            ),
            SecurityTool(
                name="trufflehog",
                command=["trufflehog", "filesystem", ".", "--json", "--output={output}"],
                output_format="json",
                description="Deep secrets detection"
            ),
            SecurityTool(
                name="detect-secrets",
                command=["detect-secrets", "scan", "--all-files", ".", ">", "{output}"],
                output_format="json",
                description="Advanced credential scanning"
            ),
            SecurityTool(
                name="retire",
                command=["retire", "--path", ".", "--outputformat", "json", "--outputpath", "{output}"],
                output_format="json",
                description="JavaScript vulnerability scanner"
            ),
            SecurityTool(
                name="jadx",
                command=["jadx", "--show-bad-code", "--export-gradle", "{output}", "*.apk"],
                output_format="text",
                description="Android APK analyzer",
                enabled=False  # Only for Android projects
            ),
            SecurityTool(
                name="apkleaks",
                command=["apkleaks", "-f", "*.apk", "-o", "{output}"],
                output_format="text",
                description="Android app secrets detection",
                enabled=False  # Only for Android projects
            ),
            SecurityTool(
                name="qark",
                command=["qark", "--apk", "*.apk", "--report-type", "json", "-o", "{output}"],
                output_format="json",
                description="Android security assessment",
                enabled=False  # Only for Android projects
            ),
            
            # Additional Enterprise Security Tools (12 more)
            SecurityTool(
                name="eslint-security",
                command=["npx", "eslint", ".", "--ext", ".js,.jsx,.ts,.tsx", "--plugin", "security", "--format", "json", "-o", "{output}"],
                output_format="json",
                description="JavaScript/TypeScript security linting"
            ),
            SecurityTool(
                name="njsscan",
                command=["njsscan", "--json", "-o", "{output}", "."],
                output_format="json",
                description="Node.js security scanner"
            ),
            SecurityTool(
                name="gosec",
                command=["gosec", "-fmt=json", "-out={output}", "./..."],
                output_format="json",
                description="Go security checker",
                enabled=False  # Only for Go projects
            ),
            SecurityTool(
                name="phpcs-security-audit",
                command=["phpcs", "--standard=Security", "--report=json", "--report-file={output}", "."],
                output_format="json",
                description="PHP security audit",
                enabled=False  # Only for PHP projects
            ),
            SecurityTool(
                name="brakeman",
                command=["brakeman", "-o", "{output}", "-f", "json"],
                output_format="json",
                description="Ruby on Rails security scanner",
                enabled=False  # Only for Ruby projects
            ),
            SecurityTool(
                name="checkov",
                command=["checkov", "-d", ".", "--output", "json", "--output-file", "{output}"],
                output_format="json",
                description="Infrastructure as Code security scanner"
            ),
            SecurityTool(
                name="tfsec",
                command=["tfsec", ".", "--format", "json", "--out", "{output}"],
                output_format="json",
                description="Terraform security scanner"
            ),
            SecurityTool(
                name="kubesec",
                command=["kubesec", "scan", "*.yaml", "-o", "json", ">", "{output}"],
                output_format="json",
                description="Kubernetes security scanner"
            ),
            SecurityTool(
                name="dependency-check",
                command=["dependency-check", "--scan", ".", "--format", "JSON", "--out", "{output}"],
                output_format="json",
                description="OWASP dependency checker"
            ),
            SecurityTool(
                name="snyk",
                command=["snyk", "test", "--json", "--json-file-output={output}"],
                output_format="json",
                description="Comprehensive vulnerability scanner"
            ),
            SecurityTool(
                name="sonarqube",
                command=["sonar-scanner", "-Dsonar.analysis.mode=preview", "-Dsonar.report.export.path={output}"],
                output_format="json",
                description="Code quality and security scanner"
            ),
            SecurityTool(
                name="codeql",
                command=["codeql", "database", "analyze", "--format=sarif-latest", "--output={output}"],
                output_format="json",
                description="GitHub's semantic code analysis"
            )
        ]
        
    async def run_tool(self, tool: SecurityTool) -> Dict[str, Any]:
        """Run a single security tool and capture results"""
        if not tool.enabled:
            return {"tool": tool.name, "status": "skipped", "reason": "Not applicable to project type"}
            
        output_file = self.results_dir / f"{tool.name}_results.{tool.output_format}"
        command = [part.replace("{output}", str(output_file)) for part in tool.command]
        
        try:
            print(f"[*] Running {tool.name}...")
            
            # Handle shell operators in command
            if ">" in command:
                shell_cmd = " ".join(command)
                result = subprocess.run(
                    shell_cmd,
                    shell=True,
                    cwd=self.repo_path,
                    capture_output=True,
                    text=True,
                    timeout=tool.timeout
                )
            else:
                result = subprocess.run(
                    command,
                    cwd=self.repo_path,
                    capture_output=True,
                    text=True,
                    timeout=tool.timeout
                )
            
            self.metrics["tools_run"] += 1
            
            # Parse results based on tool
            findings = self.parse_tool_output(tool.name, output_file)
            
            return {
                "tool": tool.name,
                "status": "success",
                "findings": findings,
                "output_file": str(output_file),
                "execution_time": result.returncode
            }
            
        except subprocess.TimeoutExpired:
            self.metrics["tools_failed"] += 1
            return {"tool": tool.name, "status": "timeout", "error": f"Tool timed out after {tool.timeout}s"}
        except Exception as e:
            self.metrics["tools_failed"] += 1
            return {"tool": tool.name, "status": "error", "error": str(e)}
            
    def parse_tool_output(self, tool_name: str, output_file: Path) -> List[Dict]:
        """Parse tool-specific output into standardized format"""
        if not output_file.exists():
            return []
            
        findings = []
        
        try:
            if tool_name == "semgrep":
                with open(output_file) as f:
                    data = json.load(f)
                    for result in data.get("results", []):
                        findings.append({
                            "severity": self.map_severity(result.get("extra", {}).get("severity", "INFO")),
                            "title": result.get("check_id", "Unknown"),
                            "description": result.get("extra", {}).get("message", ""),
                            "file": result.get("path", ""),
                            "line": result.get("start", {}).get("line", 0),
                            "cwe": result.get("extra", {}).get("metadata", {}).get("cwe", [""])[0] if result.get("extra", {}).get("metadata", {}).get("cwe") else None
                        })
                        
            elif tool_name == "gitleaks":
                with open(output_file) as f:
                    content = f.read()
                    if content.strip():
                        data = json.loads(content)
                        for leak in data:
                            findings.append({
                                "severity": "HIGH",
                                "title": f"Secret found: {leak.get('RuleID', 'Unknown')}",
                                "description": leak.get('Description', ''),
                                "file": leak.get('File', ''),
                                "line": leak.get('StartLine', 0)
                            })
                            
            # Add more tool parsers here...
            
        except Exception as e:
            print(f"[!] Error parsing {tool_name} output: {e}")
            
        return findings
        
    def map_severity(self, severity: str) -> SeverityLevel:
        """Map tool-specific severity to standard levels"""
        severity_map = {
            "ERROR": SeverityLevel.HIGH,
            "WARNING": SeverityLevel.MEDIUM,
            "INFO": SeverityLevel.INFO,
            "CRITICAL": SeverityLevel.CRITICAL,
            "HIGH": SeverityLevel.HIGH,
            "MEDIUM": SeverityLevel.MEDIUM,
            "LOW": SeverityLevel.LOW
        }
        return severity_map.get(severity.upper(), SeverityLevel.MEDIUM)
        
    async def scan_repository(self) -> Dict[str, Any]:
        """Run all security tools on the repository"""
        print(f"[*] Starting comprehensive security scan at {self.repo_path}")
        print(f"[*] Scan ID: {self.scan_id}")
        
        # Get project metrics
        self.metrics["files_scanned"] = sum(1 for _ in self.repo_path.rglob("*") if _.is_file())
        self.metrics["lines_scanned"] = self.count_lines_of_code()
        
        # Detect project type and enable relevant tools
        tools = self.detect_and_configure_tools()
        
        # Run all tools concurrently
        tasks = [self.run_tool(tool) for tool in tools if tool.enabled]
        results = await asyncio.gather(*tasks)
        
        # Aggregate findings
        all_findings = []
        for result in results:
            if result["status"] == "success":
                all_findings.extend(result.get("findings", []))
                
        # Deduplicate and score vulnerabilities
        self.vulnerabilities = self.deduplicate_findings(all_findings)
        
        self.metrics["end_time"] = datetime.now()
        self.metrics["total_vulnerabilities"] = len(self.vulnerabilities)
        self.metrics["critical_count"] = sum(1 for v in self.vulnerabilities if v.severity == SeverityLevel.CRITICAL)
        self.metrics["high_count"] = sum(1 for v in self.vulnerabilities if v.severity == SeverityLevel.HIGH)
        
        return {
            "scan_id": self.scan_id,
            "repository": str(self.repo_path),
            "metrics": self.metrics,
            "tool_results": results,
            "vulnerabilities": [self.vuln_to_dict(v) for v in self.vulnerabilities]
        }
        
    def detect_and_configure_tools(self) -> List[SecurityTool]:
        """Detect project type and enable appropriate tools"""
        tools = self.get_all_security_tools()
        
        # Check for project indicators
        has_package_json = (self.repo_path / "package.json").exists()
        has_requirements = (self.repo_path / "requirements.txt").exists()
        has_go_mod = (self.repo_path / "go.mod").exists()
        has_gemfile = (self.repo_path / "Gemfile").exists()
        has_composer = (self.repo_path / "composer.json").exists()
        has_android = any(self.repo_path.rglob("*.apk"))
        has_terraform = any(self.repo_path.rglob("*.tf"))
        has_kubernetes = any(self.repo_path.rglob("*.yaml")) or any(self.repo_path.rglob("*.yml"))
        
        # Enable tools based on project type
        for tool in tools:
            if tool.name in ["eslint-security", "njsscan", "retire"] and not has_package_json:
                tool.enabled = False
            elif tool.name in ["bandit", "safety"] and not has_requirements:
                tool.enabled = False
            elif tool.name == "gosec" and not has_go_mod:
                tool.enabled = False
            elif tool.name == "brakeman" and not has_gemfile:
                tool.enabled = False
            elif tool.name == "phpcs-security-audit" and not has_composer:
                tool.enabled = False
            elif tool.name in ["jadx", "apkleaks", "qark"] and not has_android:
                tool.enabled = False
            elif tool.name == "tfsec" and not has_terraform:
                tool.enabled = False
            elif tool.name == "kubesec" and not has_kubernetes:
                tool.enabled = False
                
        return tools
        
    def count_lines_of_code(self) -> int:
        """Count total lines of code in the repository"""
        total_lines = 0
        code_extensions = {'.py', '.js', '.ts', '.jsx', '.tsx', '.java', '.c', '.cpp', '.go', '.rb', '.php'}
        
        for file_path in self.repo_path.rglob("*"):
            if file_path.is_file() and file_path.suffix in code_extensions:
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        total_lines += sum(1 for _ in f)
                except:
                    pass
                    
        return total_lines
        
    def deduplicate_findings(self, findings: List[Dict]) -> List[Vulnerability]:
        """Deduplicate and consolidate findings from multiple tools"""
        unique_vulns = {}
        
        for finding in findings:
            # Create a hash based on file, line, and issue type
            key = hashlib.md5(
                f"{finding.get('file', '')}:{finding.get('line', 0)}:{finding.get('title', '')}".encode()
            ).hexdigest()
            
            if key not in unique_vulns:
                unique_vulns[key] = Vulnerability(
                    tool=finding.get("tool", "unknown"),
                    severity=finding.get("severity", SeverityLevel.MEDIUM),
                    title=finding.get("title", "Unknown vulnerability"),
                    description=finding.get("description", ""),
                    file_path=finding.get("file"),
                    line_number=finding.get("line"),
                    cwe=finding.get("cwe"),
                    owasp=finding.get("owasp"),
                    remediation=finding.get("remediation")
                )
            else:
                # Merge information from multiple tools
                existing = unique_vulns[key]
                if not existing.cwe and finding.get("cwe"):
                    existing.cwe = finding.get("cwe")
                if not existing.owasp and finding.get("owasp"):
                    existing.owasp = finding.get("owasp")
                    
        return list(unique_vulns.values())
        
    def vuln_to_dict(self, vuln: Vulnerability) -> Dict:
        """Convert vulnerability object to dictionary"""
        return {
            "tool": vuln.tool,
            "severity": vuln.severity.value,
            "title": vuln.title,
            "description": vuln.description,
            "file_path": vuln.file_path,
            "line_number": vuln.line_number,
            "cwe": vuln.cwe,
            "owasp": vuln.owasp,
            "remediation": vuln.remediation,
            "confidence": vuln.confidence
        }
        
    def generate_enterprise_report(self, scan_results: Dict) -> str:
        """Generate comprehensive enterprise security report"""
        from enterprise_report_generator import EnterpriseReportGenerator
        
        generator = EnterpriseReportGenerator(
            scan_results=scan_results,
            repo_path=self.repo_path,
            scan_id=self.scan_id
        )
        
        report_path = generator.generate_full_report()
        return report_path


async def main():
    """Main entry point for the comprehensive scanner"""
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python comprehensive_scanner.py <repository_path>")
        sys.exit(1)
        
    repo_path = sys.argv[1]
    scanner = ComprehensiveScanner(repo_path)
    
    # Run comprehensive scan
    results = await scanner.scan_repository()
    
    # Generate enterprise report
    report_path = scanner.generate_enterprise_report(results)
    
    print(f"\n[✓] Scan complete!")
    print(f"[✓] Total vulnerabilities found: {results['metrics']['total_vulnerabilities']}")
    print(f"[✓] Critical: {results['metrics']['critical_count']}")
    print(f"[✓] High: {results['metrics']['high_count']}")
    print(f"[✓] Report generated: {report_path}")
    
    # Save raw results
    results_file = scanner.results_dir / "scan_results.json"
    with open(results_file, 'w') as f:
        json.dump(results, f, indent=2, default=str)
        
    return results


if __name__ == "__main__":
    asyncio.run(main())