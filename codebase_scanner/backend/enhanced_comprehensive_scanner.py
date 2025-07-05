#!/usr/bin/env python3
"""
Enhanced Comprehensive Scanner - Generates truly detailed 45+ page reports
"""

import asyncio
import json
import subprocess
import os
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any
import hashlib
import re

from comprehensive_scanner import ComprehensiveScanner, SecurityTool, Vulnerability, SeverityLevel


class EnhancedComprehensiveScanner(ComprehensiveScanner):
    """Enhanced scanner that generates more detailed reports"""
    
    def __init__(self, repo_path: str):
        super().__init__(repo_path)
        self.code_samples = []
        self.file_analysis = {}
        
    def get_all_security_tools(self):
        """Return enhanced set of tools for comprehensive scanning"""
        return [
            # Core Tools
            SecurityTool(
                name="semgrep",
                command=["semgrep", "--config=auto", "--json", "--output={output}", 
                        "--metrics=off", "--max-target-bytes=50000000"],
                output_format="json",
                description="Static analysis with security rules",
                timeout=300
            ),
            SecurityTool(
                name="bandit",
                command=["bandit", "-r", ".", "-f", "json", "-o", "{output}", 
                        "--skip", "B404,B603", "-ll"],
                output_format="json",
                description="Python security linter",
                timeout=120
            ),
            SecurityTool(
                name="gitleaks",
                command=["gitleaks", "detect", "--source=.", "--report-format=json", 
                        "--report-path={output}", "--no-git", "--redact"],
                output_format="json",
                description="Git secrets scanner",
                timeout=120
            ),
            SecurityTool(
                name="trufflehog",
                command=["trufflehog", "filesystem", ".", "--json", "--only-verified"],
                output_format="json",
                description="Deep secrets detection",
                timeout=180
            ),
            SecurityTool(
                name="detect-secrets",
                command=["detect-secrets", "scan", "--all-files", ".", ">", "{output}"],
                output_format="json",
                description="Advanced credential scanning",
                timeout=120
            ),
            SecurityTool(
                name="eslint-security",
                command=["npx", "eslint", ".", "--ext", ".js,.jsx,.ts,.tsx", 
                        "--plugin", "security", "--format", "json", "-o", "{output}"],
                output_format="json",
                description="JavaScript/TypeScript security",
                timeout=180
            ),
            SecurityTool(
                name="njsscan",
                command=["njsscan", "--json", "-o", "{output}", ".", "--missing-controls"],
                output_format="json",
                description="Node.js security scanner",
                timeout=180
            ),
            SecurityTool(
                name="retire",
                command=["retire", "--path", ".", "--outputformat", "json", 
                        "--outputpath", "{output}", "--jspath", ".", "--nodepath", "."],
                output_format="json",
                description="JavaScript vulnerability scanner",
                timeout=120
            ),
            SecurityTool(
                name="npm-audit",
                command=["npm", "audit", "--json", ">", "{output}"],
                output_format="json",
                description="NPM dependency scanner",
                timeout=120
            ),
            SecurityTool(
                name="checkov",
                command=["checkov", "-d", ".", "--output", "json", "--output-file", "{output}",
                        "--framework", "all", "--download-external-modules", "false"],
                output_format="json",
                description="Infrastructure as Code scanner",
                timeout=300
            )
        ]
        
    async def analyze_codebase_deeply(self):
        """Perform deep analysis of codebase for detailed reporting"""
        print("[*] Performing deep codebase analysis...")
        
        # Analyze file types and structure
        file_stats = {
            "total_files": 0,
            "by_type": {},
            "by_size": {"small": 0, "medium": 0, "large": 0},
            "sensitive_files": []
        }
        
        code_patterns = {
            "api_endpoints": [],
            "database_queries": [],
            "authentication_points": [],
            "file_operations": [],
            "external_calls": []
        }
        
        for file_path in self.repo_path.rglob("*"):
            if file_path.is_file() and not any(skip in str(file_path) for skip in ['.git', 'node_modules', '__pycache__']):
                file_stats["total_files"] += 1
                ext = file_path.suffix
                file_stats["by_type"][ext] = file_stats["by_type"].get(ext, 0) + 1
                
                # Check file size
                size = file_path.stat().st_size
                if size < 10000:
                    file_stats["by_size"]["small"] += 1
                elif size < 100000:
                    file_stats["by_size"]["medium"] += 1
                else:
                    file_stats["by_size"]["large"] += 1
                    
                # Check for sensitive files
                sensitive_patterns = ['config', 'secret', 'key', 'password', 'token', 'auth', 'cred']
                if any(pattern in file_path.name.lower() for pattern in sensitive_patterns):
                    file_stats["sensitive_files"].append(str(file_path.relative_to(self.repo_path)))
                    
                # Analyze code patterns
                if ext in ['.js', '.ts', '.jsx', '.tsx', '.py', '.java', '.go']:
                    try:
                        content = file_path.read_text(encoding='utf-8', errors='ignore')
                        
                        # Find API endpoints
                        api_patterns = [
                            r'@app\.(route|get|post|put|delete|patch)',
                            r'router\.(get|post|put|delete|patch)',
                            r'@(Get|Post|Put|Delete|Patch)Mapping',
                            r'func\s+\w+\s*\(.*http\.ResponseWriter'
                        ]
                        for pattern in api_patterns:
                            matches = re.findall(pattern, content, re.IGNORECASE)
                            if matches:
                                code_patterns["api_endpoints"].append({
                                    "file": str(file_path.relative_to(self.repo_path)),
                                    "count": len(matches),
                                    "methods": matches
                                })
                                
                        # Find database operations
                        db_patterns = [
                            r'(SELECT|INSERT|UPDATE|DELETE|DROP)\s+',
                            r'\.query\(',
                            r'\.execute\(',
                            r'collection\.(find|insert|update|delete)',
                            r'@Query'
                        ]
                        for pattern in db_patterns:
                            if re.search(pattern, content, re.IGNORECASE):
                                code_patterns["database_queries"].append(str(file_path.relative_to(self.repo_path)))
                                break
                                
                        # Find authentication code
                        auth_patterns = [
                            r'(login|signin|authenticate|auth)',
                            r'(jwt|token|session)',
                            r'bcrypt|argon2|pbkdf2',
                            r'passport|oauth'
                        ]
                        for pattern in auth_patterns:
                            if re.search(pattern, content, re.IGNORECASE):
                                code_patterns["authentication_points"].append(str(file_path.relative_to(self.repo_path)))
                                break
                                
                        # Find file operations
                        file_patterns = [
                            r'fs\.(read|write|unlink)',
                            r'open\(.*[\'"]w',
                            r'File\(.*\)',
                            r'multer|formidable|busboy'
                        ]
                        for pattern in file_patterns:
                            if re.search(pattern, content, re.IGNORECASE):
                                code_patterns["file_operations"].append(str(file_path.relative_to(self.repo_path)))
                                break
                                
                        # Find external calls
                        external_patterns = [
                            r'(fetch|axios|request|http\.get)',
                            r'https?://[^\s]+',
                            r'\.get\([\'"]http',
                            r'requests\.(get|post)'
                        ]
                        for pattern in external_patterns:
                            if re.search(pattern, content, re.IGNORECASE):
                                code_patterns["external_calls"].append(str(file_path.relative_to(self.repo_path)))
                                break
                                
                    except Exception as e:
                        pass
                        
        self.file_analysis = {
            "stats": file_stats,
            "patterns": code_patterns
        }
        
    async def scan_repository(self) -> Dict[str, Any]:
        """Enhanced repository scanning with deep analysis"""
        # First perform deep analysis
        await self.analyze_codebase_deeply()
        
        # Then run normal scanning
        results = await super().scan_repository()
        
        # Add enhanced metrics
        results["enhanced_analysis"] = self.file_analysis
        results["metrics"]["sensitive_files"] = len(self.file_analysis["stats"]["sensitive_files"])
        results["metrics"]["api_endpoints"] = len(self.file_analysis["patterns"]["api_endpoints"])
        results["metrics"]["database_operations"] = len(self.file_analysis["patterns"]["database_queries"])
        
        return results
        
    def generate_enhanced_report(self, scan_results: Dict) -> str:
        """Generate truly comprehensive 45+ page report"""
        from enhanced_report_generator import EnhancedReportGenerator
        
        generator = EnhancedReportGenerator(
            scan_results=scan_results,
            repo_path=self.repo_path,
            scan_id=self.scan_id,
            enhanced_analysis=self.file_analysis
        )
        
        report_path = generator.generate_full_report()
        return report_path


async def main():
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python enhanced_comprehensive_scanner.py <repository_path>")
        sys.exit(1)
        
    repo_path = sys.argv[1]
    scanner = EnhancedComprehensiveScanner(repo_path)
    
    print(f"[*] Running ENHANCED comprehensive scan on {repo_path}")
    print(f"[*] This will generate a detailed 45+ page report")
    
    # Run scan
    results = await scanner.scan_repository()
    
    # Generate enhanced report
    report_path = scanner.generate_enhanced_report(results)
    
    print(f"\n[✓] Enhanced scan complete!")
    print(f"[✓] Total vulnerabilities found: {results['metrics']['total_vulnerabilities']}")
    print(f"[✓] Sensitive files detected: {results['metrics']['sensitive_files']}")
    print(f"[✓] API endpoints found: {results['metrics']['api_endpoints']}")
    print(f"[✓] Enhanced report generated: {report_path}")


if __name__ == "__main__":
    asyncio.run(main())