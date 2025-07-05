"""
Simplified scan service for production deployment
"""

import asyncio
import json
import tempfile
import subprocess
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any
import uuid


class SimplifiedScanner:
    """Simplified scanner that runs quickly with essential tools"""
    
    def __init__(self, repo_path: str):
        self.repo_path = Path(repo_path)
        self.scan_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.results_dir = self.repo_path / "scan-results" / self.scan_id
        self.results_dir.mkdir(parents=True, exist_ok=True)
        
    async def run_essential_tools(self) -> Dict[str, Any]:
        """Run only the essential and fast tools"""
        results = {
            "scan_id": self.scan_id,
            "scan_time": datetime.now().isoformat(),
            "tools": {},
            "vulnerabilities": [],
            "summary": {
                "total_issues": 0,
                "high_severity": 0,
                "secrets_found": 0
            }
        }
        
        # Run Semgrep (fast and comprehensive)
        try:
            print("[*] Running Semgrep...")
            semgrep_cmd = [
                "semgrep", "--config=auto", "--json", 
                "--timeout=30",
                str(self.repo_path)
            ]
            
            result = await asyncio.create_subprocess_exec(
                *semgrep_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await asyncio.wait_for(result.communicate(), timeout=60)
            
            if result.returncode == 0 and stdout:
                data = json.loads(stdout)
                findings = data.get("results", [])
                results["tools"]["semgrep"] = {
                    "status": "success",
                    "findings": len(findings)
                }
                results["summary"]["total_issues"] += len(findings)
                results["summary"]["high_severity"] += sum(
                    1 for f in findings 
                    if f.get("extra", {}).get("severity", "").upper() in ["HIGH", "ERROR"]
                )
                
                # Add top findings to vulnerabilities
                for finding in findings[:5]:  # Top 5 only
                    results["vulnerabilities"].append({
                        "tool": "semgrep",
                        "severity": finding.get("extra", {}).get("severity", "MEDIUM"),
                        "title": finding.get("check_id", "Unknown"),
                        "file": finding.get("path", ""),
                        "line": finding.get("start", {}).get("line", 0),
                        "message": finding.get("extra", {}).get("message", "")
                    })
            else:
                results["tools"]["semgrep"] = {"status": "failed", "error": stderr.decode() if stderr else "Unknown error"}
                
        except Exception as e:
            results["tools"]["semgrep"] = {"status": "error", "error": str(e)}
            
        # Run Gitleaks (fast secrets detection)
        try:
            print("[*] Running Gitleaks...")
            gitleaks_output = self.results_dir / "gitleaks.json"
            gitleaks_cmd = [
                "gitleaks", "detect", "--source", str(self.repo_path),
                "--report-format", "json", "--report-path", str(gitleaks_output),
                "--no-git", "--redact"
            ]
            
            result = await asyncio.create_subprocess_exec(
                *gitleaks_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await asyncio.wait_for(result.communicate(), timeout=30)
            
            if gitleaks_output.exists():
                with open(gitleaks_output) as f:
                    content = f.read()
                    if content.strip():
                        leaks = json.loads(content)
                        results["tools"]["gitleaks"] = {
                            "status": "success",
                            "secrets_found": len(leaks) if isinstance(leaks, list) else 0
                        }
                        results["summary"]["secrets_found"] += len(leaks) if isinstance(leaks, list) else 0
                    else:
                        results["tools"]["gitleaks"] = {"status": "success", "secrets_found": 0}
            else:
                results["tools"]["gitleaks"] = {"status": "success", "secrets_found": 0}
                
        except Exception as e:
            results["tools"]["gitleaks"] = {"status": "error", "error": str(e)}
            
        # Run Bandit (Python security)
        if any(self.repo_path.rglob("*.py")):
            try:
                print("[*] Running Bandit...")
                bandit_output = self.results_dir / "bandit.json"
                bandit_cmd = [
                    "bandit", "-r", str(self.repo_path), "-f", "json",
                    "-o", str(bandit_output), "--skip", "B404,B603", "-ll"
                ]
                
                result = await asyncio.create_subprocess_exec(
                    *bandit_cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, stderr = await asyncio.wait_for(result.communicate(), timeout=30)
                
                if bandit_output.exists():
                    with open(bandit_output) as f:
                        data = json.load(f)
                        findings = data.get("results", [])
                        results["tools"]["bandit"] = {
                            "status": "success",
                            "findings": len(findings)
                        }
                        results["summary"]["total_issues"] += len(findings)
                        
                        # Add findings
                        for finding in findings[:3]:  # Top 3 only
                            results["vulnerabilities"].append({
                                "tool": "bandit",
                                "severity": finding.get("issue_severity", "MEDIUM"),
                                "title": finding.get("issue_text", ""),
                                "file": finding.get("filename", ""),
                                "line": finding.get("line_number", 0),
                                "message": finding.get("issue_text", "")
                            })
                else:
                    results["tools"]["bandit"] = {"status": "success", "findings": 0}
                    
            except Exception as e:
                results["tools"]["bandit"] = {"status": "error", "error": str(e)}
                
        return results


async def quick_security_scan(repository_url: str, branch: str = "main") -> Dict[str, Any]:
    """Perform a quick security scan with essential tools"""
    with tempfile.TemporaryDirectory() as temp_dir:
        # Clone repository
        repo_path = Path(temp_dir) / "repo"
        clone_cmd = ["git", "clone", "--depth", "1", "-b", branch, repository_url, str(repo_path)]
        
        clone_result = subprocess.run(clone_cmd, capture_output=True, text=True, timeout=30)
        
        if clone_result.returncode != 0:
            return {"error": f"Failed to clone repository: {clone_result.stderr}"}
            
        # Run simplified scanner
        scanner = SimplifiedScanner(str(repo_path))
        results = await scanner.run_essential_tools()
        
        return results