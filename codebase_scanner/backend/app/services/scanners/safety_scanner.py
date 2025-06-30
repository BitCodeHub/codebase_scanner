"""
Safety scanner module for dependency vulnerability analysis.
"""

import asyncio
import json
import logging
import os
import tempfile
from pathlib import Path
from typing import Dict, List, Any, Optional

logger = logging.getLogger(__name__)


class SafetyScanner:
    """
    Safety scanner for Python dependency vulnerability detection.
    
    Safety checks Python dependencies for known security vulnerabilities.
    """
    
    def __init__(self):
        """Initialize Safety scanner."""
        self.name = "safety"
        self.requirements_files = [
            "requirements.txt",
            "requirements.in",
            "requirements-dev.txt",
            "requirements-test.txt",
            "Pipfile",
            "Pipfile.lock",
            "pyproject.toml",
            "poetry.lock",
            "setup.py",
            "setup.cfg"
        ]
    
    async def scan(
        self,
        target_path: str,
        config: Optional[Dict[str, Any]] = None
    ) -> List[Dict[str, Any]]:
        """
        Run Safety scan on Python dependencies.
        
        Args:
            target_path: Path to scan
            config: Optional scanner configuration
            
        Returns:
            List of findings
        """
        try:
            # Find dependency files
            dep_files = self._find_dependency_files(target_path)
            if not dep_files:
                logger.info("No Python dependency files found for Safety scan")
                return []
            
            all_findings = []
            
            for dep_file in dep_files:
                findings = await self._scan_file(dep_file, config)
                all_findings.extend(findings)
            
            # Deduplicate findings
            unique_findings = self._deduplicate_findings(all_findings)
            
            logger.info(f"Safety scan completed. Found {len(unique_findings)} vulnerabilities")
            return unique_findings
            
        except FileNotFoundError:
            logger.error("Safety not found. Please install safety")
            return []
        except Exception as e:
            logger.error(f"Safety scan failed: {e}")
            return []
    
    async def _scan_file(
        self,
        dep_file: str,
        config: Optional[Dict[str, Any]] = None
    ) -> List[Dict[str, Any]]:
        """
        Scan a single dependency file.
        
        Args:
            dep_file: Path to dependency file
            config: Optional configuration
            
        Returns:
            List of findings for this file
        """
        output_file = tempfile.NamedTemporaryFile(
            mode='w',
            suffix='.json',
            delete=False
        )
        output_file.close()
        
        # Build Safety command
        cmd = [
            "safety",
            "check",
            "--json",
            "--output", output_file.name
        ]
        
        # Add file-specific options based on file type
        file_name = os.path.basename(dep_file)
        if file_name in ["requirements.txt", "requirements.in", "requirements-dev.txt", "requirements-test.txt"]:
            cmd.extend(["--file", dep_file])
        elif file_name == "Pipfile" or file_name == "Pipfile.lock":
            # For Pipfile, we need to generate requirements first
            req_file = await self._pipfile_to_requirements(dep_file)
            if req_file:
                cmd.extend(["--file", req_file])
            else:
                return []
        elif file_name == "poetry.lock" or file_name == "pyproject.toml":
            # For poetry, export to requirements format
            req_file = await self._poetry_to_requirements(dep_file)
            if req_file:
                cmd.extend(["--file", req_file])
            else:
                return []
        else:
            cmd.extend(["--file", dep_file])
        
        # Add configuration options
        if config:
            if config.get("ignore_vulns"):
                for vuln_id in config["ignore_vulns"]:
                    cmd.extend(["--ignore", vuln_id])
            
            if config.get("db_path"):
                cmd.extend(["--db", config["db_path"]])
        
        # Run Safety
        logger.info(f"Running Safety scan on {dep_file}")
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=os.path.dirname(dep_file)
        )
        
        stdout, stderr = await process.communicate()
        
        # Parse results
        findings = []
        if os.path.exists(output_file.name):
            try:
                with open(output_file.name, 'r') as f:
                    data = json.load(f)
                    findings = self._parse_results(data, dep_file)
            except json.JSONDecodeError:
                # Sometimes safety outputs to stdout instead
                try:
                    data = json.loads(stdout.decode())
                    findings = self._parse_results(data, dep_file)
                except:
                    pass
            finally:
                os.unlink(output_file.name)
        
        return findings
    
    def _find_dependency_files(self, target_path: str) -> List[str]:
        """
        Find Python dependency files in the target path.
        
        Args:
            target_path: Path to search
            
        Returns:
            List of dependency file paths
        """
        dep_files = []
        path = Path(target_path)
        
        if path.is_file():
            if path.name in self.requirements_files:
                dep_files.append(str(path))
        else:
            # Search for dependency files
            for req_file in self.requirements_files:
                for found_file in path.rglob(req_file):
                    dep_files.append(str(found_file))
        
        return list(set(dep_files))  # Remove duplicates
    
    async def _pipfile_to_requirements(self, pipfile_path: str) -> Optional[str]:
        """
        Convert Pipfile to requirements.txt format.
        
        Args:
            pipfile_path: Path to Pipfile
            
        Returns:
            Path to generated requirements file or None
        """
        try:
            req_file = tempfile.NamedTemporaryFile(
                mode='w',
                suffix='_requirements.txt',
                delete=False
            )
            req_file.close()
            
            # Try to use pipenv to generate requirements
            process = await asyncio.create_subprocess_exec(
                "pipenv",
                "requirements",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=os.path.dirname(pipfile_path)
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                with open(req_file.name, 'w') as f:
                    f.write(stdout.decode())
                return req_file.name
            
            os.unlink(req_file.name)
            return None
            
        except:
            return None
    
    async def _poetry_to_requirements(self, poetry_file: str) -> Optional[str]:
        """
        Convert poetry.lock to requirements.txt format.
        
        Args:
            poetry_file: Path to poetry.lock or pyproject.toml
            
        Returns:
            Path to generated requirements file or None
        """
        try:
            req_file = tempfile.NamedTemporaryFile(
                mode='w',
                suffix='_requirements.txt',
                delete=False
            )
            req_file.close()
            
            # Try to use poetry to export requirements
            process = await asyncio.create_subprocess_exec(
                "poetry",
                "export",
                "--format", "requirements.txt",
                "--output", req_file.name,
                "--without-hashes",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=os.path.dirname(poetry_file)
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                return req_file.name
            
            os.unlink(req_file.name)
            return None
            
        except:
            return None
    
    def _parse_results(self, safety_output: Any, source_file: str) -> List[Dict[str, Any]]:
        """
        Parse Safety output into standardized format.
        
        Args:
            safety_output: Raw Safety output (can be list or dict)
            source_file: Source dependency file
            
        Returns:
            List of standardized findings
        """
        findings = []
        
        # Safety output can be in different formats
        vulnerabilities = []
        if isinstance(safety_output, list):
            vulnerabilities = safety_output
        elif isinstance(safety_output, dict):
            vulnerabilities = safety_output.get("vulnerabilities", [])
        
        for vuln in vulnerabilities:
            finding = {
                "scanner": self.name,
                "rule_id": f"safety-{vuln.get('vulnerability_id', 'unknown')}",
                "title": f"Vulnerable dependency: {vuln.get('package_name', 'unknown')}",
                "description": vuln.get("description", ""),
                "severity": self._map_severity(vuln),
                "category": "vulnerable-dependency",
                "file_path": source_file,
                "line_start": 0,  # Safety doesn't provide line numbers
                "line_end": 0,
                "package_name": vuln.get("package_name", ""),
                "installed_version": vuln.get("installed_version", ""),
                "affected_versions": vuln.get("affected_versions", []),
                "vulnerability_id": vuln.get("vulnerability_id", ""),
                "cve": self._extract_cve(vuln),
                "cvss_score": vuln.get("cvss", {}).get("score", 0) if isinstance(vuln.get("cvss"), dict) else 0,
                "fix_guidance": self._get_fix_guidance(vuln),
                "references": vuln.get("more_info_urls", []),
                "raw_output": vuln
            }
            
            findings.append(finding)
        
        return findings
    
    def _map_severity(self, vuln: Dict[str, Any]) -> str:
        """
        Map vulnerability to severity level.
        
        Args:
            vuln: Vulnerability data
            
        Returns:
            Standardized severity level
        """
        # Try to use CVSS score if available
        cvss = vuln.get("cvss", {})
        if isinstance(cvss, dict):
            score = cvss.get("score", 0)
            if score >= 9.0:
                return "critical"
            elif score >= 7.0:
                return "high"
            elif score >= 4.0:
                return "medium"
            else:
                return "low"
        
        # Fallback to severity field
        severity = vuln.get("severity", "").lower()
        if severity in ["critical", "high", "medium", "low"]:
            return severity
        
        return "medium"  # Default
    
    def _extract_cve(self, vuln: Dict[str, Any]) -> Optional[str]:
        """
        Extract CVE ID from vulnerability.
        
        Args:
            vuln: Vulnerability data
            
        Returns:
            CVE ID or None
        """
        # Check direct CVE field
        if vuln.get("cve"):
            return vuln["cve"]
        
        # Check in advisory
        advisory = vuln.get("advisory", "")
        if "CVE-" in advisory:
            import re
            cve_match = re.search(r'CVE-\d{4}-\d+', advisory)
            if cve_match:
                return cve_match.group()
        
        return None
    
    def _get_fix_guidance(self, vuln: Dict[str, Any]) -> str:
        """
        Generate fix guidance for vulnerability.
        
        Args:
            vuln: Vulnerability data
            
        Returns:
            Fix guidance string
        """
        package = vuln.get("package_name", "unknown")
        current = vuln.get("installed_version", "unknown")
        
        # Check if there's a safe version specified
        safe_versions = []
        affected = vuln.get("affected_versions", [])
        
        if isinstance(affected, str):
            # Parse affected versions to suggest fix
            if ">=" in affected and "<" in affected:
                # Extract upper bound as potential safe version
                parts = affected.split("<")
                if len(parts) > 1:
                    safe_version = parts[1].strip()
                    return f"Update {package} to version {safe_version} or higher"
        
        # Generic guidance
        return f"Update {package} from {current} to a patched version. Check the references for safe versions."
    
    def _deduplicate_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Deduplicate findings based on package and vulnerability ID.
        
        Args:
            findings: List of findings
            
        Returns:
            Deduplicated list of findings
        """
        seen = set()
        unique = []
        
        for finding in findings:
            key = (
                finding.get("package_name"),
                finding.get("vulnerability_id"),
                finding.get("installed_version")
            )
            
            if key not in seen:
                seen.add(key)
                unique.append(finding)
        
        return unique