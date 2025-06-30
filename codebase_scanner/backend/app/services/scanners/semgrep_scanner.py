"""
Semgrep scanner module for SAST (Static Application Security Testing) analysis.
"""

import asyncio
import json
import logging
import os
import subprocess
import tempfile
from pathlib import Path
from typing import Dict, List, Any, Optional

logger = logging.getLogger(__name__)


class SemgrepScanner:
    """
    Semgrep scanner for comprehensive static analysis.
    
    Semgrep is a fast, open-source static analysis tool that finds bugs,
    security vulnerabilities, and anti-patterns in code.
    """
    
    def __init__(self):
        """Initialize Semgrep scanner."""
        self.name = "semgrep"
        self.default_rulesets = [
            "auto",  # Automatically detect and use appropriate rules
            "r2c-security-audit",  # Security audit rules
            "r2c-ci",  # CI/CD appropriate rules
        ]
    
    async def scan(
        self,
        target_path: str,
        config: Optional[Dict[str, Any]] = None
    ) -> List[Dict[str, Any]]:
        """
        Run Semgrep scan on the target path.
        
        Args:
            target_path: Path to scan
            config: Optional scanner configuration
            
        Returns:
            List of findings
        """
        try:
            # Prepare scan configuration
            rulesets = self._get_rulesets(config)
            output_file = tempfile.NamedTemporaryFile(
                mode='w',
                suffix='.json',
                delete=False
            )
            output_file.close()
            
            # Build Semgrep command
            cmd = [
                "semgrep",
                "--config=" + ",".join(rulesets),
                "--json",
                "--output", output_file.name,
                "--metrics=off",  # Disable telemetry
                "--quiet",
                target_path
            ]
            
            # Add additional options from config
            if config:
                if config.get("exclude_patterns"):
                    for pattern in config["exclude_patterns"]:
                        cmd.extend(["--exclude", pattern])
                
                if config.get("include_patterns"):
                    for pattern in config["include_patterns"]:
                        cmd.extend(["--include", pattern])
                
                if config.get("max_file_size"):
                    cmd.extend(["--max-target-bytes", str(config["max_file_size"])])
            
            # Run Semgrep
            logger.info(f"Running Semgrep scan on {target_path}")
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            # Parse results
            findings = []
            if os.path.exists(output_file.name):
                with open(output_file.name, 'r') as f:
                    data = json.load(f)
                    findings = self._parse_results(data)
                os.unlink(output_file.name)
            
            if process.returncode not in [0, 1]:  # 0 = success, 1 = findings found
                logger.error(f"Semgrep scan failed: {stderr.decode()}")
                return []
            
            logger.info(f"Semgrep scan completed. Found {len(findings)} issues")
            return findings
            
        except FileNotFoundError:
            logger.error("Semgrep not found. Please install semgrep")
            return []
        except Exception as e:
            logger.error(f"Semgrep scan failed: {e}")
            return []
    
    def _get_rulesets(self, config: Optional[Dict[str, Any]] = None) -> List[str]:
        """
        Get rulesets to use for scanning.
        
        Args:
            config: Optional configuration
            
        Returns:
            List of ruleset identifiers
        """
        if config and "rulesets" in config:
            return config["rulesets"]
        return self.default_rulesets
    
    def _parse_results(self, semgrep_output: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Parse Semgrep JSON output into standardized format.
        
        Args:
            semgrep_output: Raw Semgrep JSON output
            
        Returns:
            List of standardized findings
        """
        findings = []
        
        for result in semgrep_output.get("results", []):
            finding = {
                "scanner": self.name,
                "rule_id": result.get("check_id", ""),
                "title": result.get("extra", {}).get("message", result.get("check_id", "")),
                "description": result.get("extra", {}).get("metadata", {}).get("description", ""),
                "severity": self._map_severity(result.get("extra", {}).get("severity", "INFO")),
                "category": self._determine_category(result),
                "file_path": result.get("path", ""),
                "line_start": result.get("start", {}).get("line", 0),
                "line_end": result.get("end", {}).get("line", 0),
                "column_start": result.get("start", {}).get("col", 0),
                "column_end": result.get("end", {}).get("col", 0),
                "code_snippet": result.get("extra", {}).get("lines", ""),
                "fix_guidance": result.get("extra", {}).get("metadata", {}).get("fix", ""),
                "references": result.get("extra", {}).get("metadata", {}).get("references", []),
                "cwe": self._extract_cwe(result),
                "owasp": self._extract_owasp(result),
                "confidence": result.get("extra", {}).get("metadata", {}).get("confidence", "MEDIUM"),
                "raw_output": result
            }
            
            findings.append(finding)
        
        return findings
    
    def _map_severity(self, semgrep_severity: str) -> str:
        """
        Map Semgrep severity to standardized severity levels.
        
        Args:
            semgrep_severity: Semgrep severity string
            
        Returns:
            Standardized severity level
        """
        severity_map = {
            "ERROR": "critical",
            "WARNING": "high",
            "INFO": "medium",
            "NOTE": "low"
        }
        
        return severity_map.get(semgrep_severity.upper(), "info")
    
    def _determine_category(self, result: Dict[str, Any]) -> str:
        """
        Determine the category of the finding.
        
        Args:
            result: Semgrep result
            
        Returns:
            Category string
        """
        check_id = result.get("check_id", "").lower()
        metadata = result.get("extra", {}).get("metadata", {})
        
        # Check for specific categories in check_id or metadata
        if any(keyword in check_id for keyword in ["sqli", "injection", "xss", "xxe"]):
            return "injection"
        elif any(keyword in check_id for keyword in ["auth", "session", "jwt", "password"]):
            return "authentication"
        elif any(keyword in check_id for keyword in ["crypto", "hash", "encrypt"]):
            return "cryptography"
        elif any(keyword in check_id for keyword in ["path", "file", "directory"]):
            return "path-traversal"
        elif any(keyword in check_id for keyword in ["ssrf", "request", "url"]):
            return "ssrf"
        elif any(keyword in check_id for keyword in ["secret", "key", "token", "credential"]):
            return "secrets"
        elif metadata.get("category"):
            return metadata["category"]
        else:
            return "security-misconfiguration"
    
    def _extract_cwe(self, result: Dict[str, Any]) -> Optional[str]:
        """
        Extract CWE ID from result if available.
        
        Args:
            result: Semgrep result
            
        Returns:
            CWE ID or None
        """
        metadata = result.get("extra", {}).get("metadata", {})
        cwe = metadata.get("cwe")
        
        if isinstance(cwe, list) and cwe:
            return cwe[0]
        elif isinstance(cwe, str):
            return cwe
        
        return None
    
    def _extract_owasp(self, result: Dict[str, Any]) -> Optional[str]:
        """
        Extract OWASP category from result if available.
        
        Args:
            result: Semgrep result
            
        Returns:
            OWASP category or None
        """
        metadata = result.get("extra", {}).get("metadata", {})
        owasp = metadata.get("owasp")
        
        if isinstance(owasp, list) and owasp:
            return owasp[0]
        elif isinstance(owasp, str):
            return owasp
        
        return None