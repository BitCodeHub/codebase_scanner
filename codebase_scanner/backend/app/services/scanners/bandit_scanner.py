"""
Bandit scanner module for Python security analysis.
"""

import asyncio
import json
import logging
import os
import tempfile
from pathlib import Path
from typing import Dict, List, Any, Optional

logger = logging.getLogger(__name__)


class BanditScanner:
    """
    Bandit scanner for Python-specific security analysis.
    
    Bandit is a tool designed to find common security issues in Python code.
    """
    
    def __init__(self):
        """Initialize Bandit scanner."""
        self.name = "bandit"
        self.severity_levels = ["LOW", "MEDIUM", "HIGH"]
        self.confidence_levels = ["LOW", "MEDIUM", "HIGH"]
    
    async def scan(
        self,
        target_path: str,
        config: Optional[Dict[str, Any]] = None
    ) -> List[Dict[str, Any]]:
        """
        Run Bandit scan on Python files in the target path.
        
        Args:
            target_path: Path to scan
            config: Optional scanner configuration
            
        Returns:
            List of findings
        """
        try:
            # Check if target contains Python files
            if not self._has_python_files(target_path):
                logger.info("No Python files found for Bandit scan")
                return []
            
            output_file = tempfile.NamedTemporaryFile(
                mode='w',
                suffix='.json',
                delete=False
            )
            output_file.close()
            
            # Build Bandit command
            cmd = [
                "bandit",
                "-r",  # Recursive
                "-f", "json",  # JSON output format
                "-o", output_file.name,  # Output file
                target_path
            ]
            
            # Add configuration options
            if config:
                if config.get("severity_level"):
                    cmd.extend(["-l", config["severity_level"]])
                else:
                    cmd.extend(["-l", "LOW"])  # Include all severity levels
                
                if config.get("confidence_level"):
                    cmd.extend(["-i", config["confidence_level"]])
                else:
                    cmd.extend(["-i", "LOW"])  # Include all confidence levels
                
                if config.get("skip_tests"):
                    cmd.extend(["-s", ",".join(config["skip_tests"])])
                
                if config.get("exclude_paths"):
                    cmd.extend(["-x", ",".join(config["exclude_paths"])])
            else:
                # Default: include all findings
                cmd.extend(["-l", "LOW", "-i", "LOW"])
            
            # Run Bandit
            logger.info(f"Running Bandit scan on {target_path}")
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
            
            if process.returncode not in [0, 1]:  # 0 = no issues, 1 = issues found
                logger.error(f"Bandit scan failed: {stderr.decode()}")
                return []
            
            logger.info(f"Bandit scan completed. Found {len(findings)} issues")
            return findings
            
        except FileNotFoundError:
            logger.error("Bandit not found. Please install bandit")
            return []
        except Exception as e:
            logger.error(f"Bandit scan failed: {e}")
            return []
    
    def _has_python_files(self, target_path: str) -> bool:
        """
        Check if the target path contains Python files.
        
        Args:
            target_path: Path to check
            
        Returns:
            True if Python files are found
        """
        path = Path(target_path)
        if path.is_file():
            return path.suffix == '.py'
        
        # Check directory recursively
        for py_file in path.rglob('*.py'):
            return True
        
        return False
    
    def _parse_results(self, bandit_output: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Parse Bandit JSON output into standardized format.
        
        Args:
            bandit_output: Raw Bandit JSON output
            
        Returns:
            List of standardized findings
        """
        findings = []
        
        for result in bandit_output.get("results", []):
            finding = {
                "scanner": self.name,
                "rule_id": result.get("test_id", ""),
                "title": result.get("test_name", ""),
                "description": result.get("issue_text", ""),
                "severity": self._map_severity(result.get("issue_severity", "LOW")),
                "category": self._determine_category(result),
                "file_path": result.get("filename", ""),
                "line_start": result.get("line_number", 0),
                "line_end": result.get("line_number", 0),
                "column_start": result.get("col_offset", 0),
                "column_end": result.get("col_offset", 0),
                "code_snippet": result.get("code", ""),
                "fix_guidance": self._get_fix_guidance(result),
                "references": [result.get("more_info", "")] if result.get("more_info") else [],
                "cwe": self._extract_cwe(result),
                "confidence": result.get("issue_confidence", "MEDIUM"),
                "test_id": result.get("test_id", ""),
                "raw_output": result
            }
            
            findings.append(finding)
        
        return findings
    
    def _map_severity(self, bandit_severity: str) -> str:
        """
        Map Bandit severity to standardized severity levels.
        
        Args:
            bandit_severity: Bandit severity string
            
        Returns:
            Standardized severity level
        """
        severity_map = {
            "HIGH": "high",
            "MEDIUM": "medium",
            "LOW": "low"
        }
        
        return severity_map.get(bandit_severity.upper(), "info")
    
    def _determine_category(self, result: Dict[str, Any]) -> str:
        """
        Determine the category of the finding based on test ID.
        
        Args:
            result: Bandit result
            
        Returns:
            Category string
        """
        test_id = result.get("test_id", "").upper()
        
        # Map Bandit test IDs to categories
        category_map = {
            # Injection
            "B601": "injection",  # Shell injection
            "B602": "injection",  # Subprocess shell=True
            "B603": "injection",  # Subprocess without shell equals true
            "B604": "injection",  # Shell usage
            "B605": "injection",  # Start process with shell
            "B606": "injection",  # Start process with no shell
            "B607": "injection",  # Start process with partial path
            "B608": "injection",  # SQL injection
            "B609": "injection",  # Wildcard injection
            
            # Cryptography
            "B303": "cryptography",  # Insecure hash functions
            "B304": "cryptography",  # Insecure cipher
            "B305": "cryptography",  # Insecure cipher mode
            "B413": "cryptography",  # pyCrypto
            "B414": "cryptography",  # pycryptodome
            
            # Random
            "B311": "cryptography",  # Random usage
            
            # Authentication/Secrets
            "B104": "secrets",  # Hardcoded bind all interfaces
            "B105": "secrets",  # Hardcoded password string
            "B106": "secrets",  # Hardcoded password function
            "B107": "secrets",  # Hardcoded password default
            
            # Deserialization
            "B301": "deserialization",  # Pickle usage
            "B302": "deserialization",  # Marshal usage
            "B306": "deserialization",  # mktemp usage
            "B307": "deserialization",  # Eval usage
            "B308": "deserialization",  # Mark safe usage
            "B309": "deserialization",  # HTTPSConnection usage
            "B310": "deserialization",  # URL open usage
            
            # File operations
            "B401": "path-traversal",  # Import telnetlib
            "B402": "path-traversal",  # Import ftplib
            "B404": "path-traversal",  # Import subprocess
            "B405": "path-traversal",  # Import xml etree
            "B406": "path-traversal",  # Import xml sax
            "B407": "path-traversal",  # Import xml expat
            "B408": "path-traversal",  # Import xml minidom
            "B409": "path-traversal",  # Import xml pulldom
            "B410": "path-traversal",  # Import lxml
            
            # Network
            "B201": "security-misconfiguration",  # Flask debug
            "B501": "security-misconfiguration",  # Request verify disable
            "B502": "security-misconfiguration",  # SSL insecure version
            "B503": "security-misconfiguration",  # SSL no validation
            "B504": "security-misconfiguration",  # SSL no host validation
            "B505": "security-misconfiguration",  # Weak cryptographic key
            "B506": "security-misconfiguration",  # yaml load
            "B507": "security-misconfiguration",  # SSH no host key verification
        }
        
        return category_map.get(test_id, "security-misconfiguration")
    
    def _get_fix_guidance(self, result: Dict[str, Any]) -> str:
        """
        Get fix guidance for the finding.
        
        Args:
            result: Bandit result
            
        Returns:
            Fix guidance string
        """
        test_id = result.get("test_id", "").upper()
        
        # Common fix guidance based on test ID
        fix_map = {
            "B601": "Avoid using shell=True in subprocess calls. Use a list of arguments instead.",
            "B602": "Remove shell=True parameter and pass command as a list.",
            "B303": "Use SHA256 or SHA3 instead of MD5 or SHA1 for cryptographic purposes.",
            "B311": "Use secrets module instead of random for security-sensitive operations.",
            "B105": "Remove hardcoded passwords. Use environment variables or secure key management.",
            "B301": "Avoid using pickle for untrusted data. Use JSON or other safe formats.",
            "B307": "Never use eval() on untrusted input. Parse data safely instead.",
            "B201": "Disable Flask debug mode in production.",
            "B501": "Always verify SSL certificates in requests.",
        }
        
        return fix_map.get(test_id, "Review the security implications and apply appropriate fixes.")
    
    def _extract_cwe(self, result: Dict[str, Any]) -> Optional[str]:
        """
        Extract CWE ID based on Bandit test ID.
        
        Args:
            result: Bandit result
            
        Returns:
            CWE ID or None
        """
        test_id = result.get("test_id", "").upper()
        
        # Map common Bandit tests to CWE IDs
        cwe_map = {
            "B601": "CWE-78",   # OS Command Injection
            "B602": "CWE-78",   # OS Command Injection
            "B608": "CWE-89",   # SQL Injection
            "B303": "CWE-327",  # Use of Broken Crypto
            "B304": "CWE-327",  # Use of Broken Crypto
            "B311": "CWE-330",  # Use of Insufficiently Random Values
            "B105": "CWE-798",  # Hardcoded Credentials
            "B106": "CWE-798",  # Hardcoded Credentials
            "B301": "CWE-502",  # Deserialization of Untrusted Data
            "B307": "CWE-95",   # Code Injection
            "B201": "CWE-489",  # Debug Mode
            "B501": "CWE-295",  # Certificate Validation
        }
        
        return cwe_map.get(test_id)