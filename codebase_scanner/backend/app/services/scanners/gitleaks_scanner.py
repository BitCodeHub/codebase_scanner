"""
Gitleaks scanner module for secret detection.
"""

import asyncio
import json
import logging
import os
import tempfile
from pathlib import Path
from typing import Dict, List, Any, Optional

logger = logging.getLogger(__name__)


class GitleaksScanner:
    """
    Gitleaks scanner for detecting secrets and sensitive information.
    
    Gitleaks is a tool for detecting hardcoded secrets like passwords,
    API keys, and tokens in git repos and files.
    """
    
    def __init__(self):
        """Initialize Gitleaks scanner."""
        self.name = "gitleaks"
        self.secret_patterns = {
            "aws_access_key": "AWS Access Key",
            "aws_secret_key": "AWS Secret Key",
            "azure_key": "Azure Key",
            "github_token": "GitHub Token",
            "google_api_key": "Google API Key",
            "private_key": "Private Key",
            "slack_token": "Slack Token",
            "stripe_key": "Stripe Key",
            "jwt": "JWT Token",
            "password": "Hardcoded Password",
            "api_key": "API Key",
            "secret": "Generic Secret"
        }
    
    async def scan(
        self,
        target_path: str,
        config: Optional[Dict[str, Any]] = None
    ) -> List[Dict[str, Any]]:
        """
        Run Gitleaks scan on the target path.
        
        Args:
            target_path: Path to scan
            config: Optional scanner configuration
            
        Returns:
            List of findings
        """
        try:
            output_file = tempfile.NamedTemporaryFile(
                mode='w',
                suffix='.json',
                delete=False
            )
            output_file.close()
            
            # Build Gitleaks command
            cmd = [
                "gitleaks",
                "detect",
                "--source", target_path,
                "--report-format", "json",
                "--report-path", output_file.name,
                "--no-git",  # Scan files directly, not git history
                "--verbose"
            ]
            
            # Add configuration options
            if config:
                if config.get("config_file"):
                    cmd.extend(["--config", config["config_file"]])
                
                if config.get("enable_git_history", False):
                    cmd.remove("--no-git")
                    cmd.append("--log-opts=--all")
                
                if config.get("max_target_megabytes"):
                    cmd.extend(["--max-target-megabytes", str(config["max_target_megabytes"])])
                
                if config.get("exclude_paths"):
                    for path in config["exclude_paths"]:
                        cmd.extend(["--exclude-path", path])
            
            # Run Gitleaks
            logger.info(f"Running Gitleaks scan on {target_path}")
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            # Parse results
            findings = []
            if os.path.exists(output_file.name):
                try:
                    with open(output_file.name, 'r') as f:
                        content = f.read()
                        if content:
                            data = json.loads(content)
                            findings = self._parse_results(data)
                except json.JSONDecodeError as e:
                    logger.error(f"Failed to parse Gitleaks output: {e}")
                finally:
                    os.unlink(output_file.name)
            
            # Gitleaks returns 1 if secrets found, 0 if clean
            if process.returncode not in [0, 1]:
                logger.error(f"Gitleaks scan failed with code {process.returncode}: {stderr.decode()}")
                return []
            
            logger.info(f"Gitleaks scan completed. Found {len(findings)} secrets")
            return findings
            
        except FileNotFoundError:
            logger.error("Gitleaks not found. Please install gitleaks")
            return []
        except Exception as e:
            logger.error(f"Gitleaks scan failed: {e}")
            return []
    
    def _parse_results(self, gitleaks_output: Any) -> List[Dict[str, Any]]:
        """
        Parse Gitleaks JSON output into standardized format.
        
        Args:
            gitleaks_output: Raw Gitleaks output
            
        Returns:
            List of standardized findings
        """
        findings = []
        
        # Handle both array and single object outputs
        if isinstance(gitleaks_output, dict):
            gitleaks_output = [gitleaks_output]
        elif not isinstance(gitleaks_output, list):
            return []
        
        for result in gitleaks_output:
            # Skip if not a valid finding
            if not isinstance(result, dict) or not result.get("Description"):
                continue
            
            finding = {
                "scanner": self.name,
                "rule_id": result.get("RuleID", "gitleaks-unknown"),
                "title": self._get_secret_title(result),
                "description": result.get("Description", "Potential secret detected"),
                "severity": self._determine_severity(result),
                "category": "secrets",
                "file_path": result.get("File", ""),
                "line_start": result.get("StartLine", 0),
                "line_end": result.get("EndLine", result.get("StartLine", 0)),
                "column_start": result.get("StartColumn", 0),
                "column_end": result.get("EndColumn", 0),
                "code_snippet": self._sanitize_secret(result.get("Secret", "")),
                "match": self._sanitize_secret(result.get("Match", "")),
                "secret_type": self._determine_secret_type(result),
                "entropy": result.get("Entropy", 0),
                "author": result.get("Author", ""),
                "email": result.get("Email", ""),
                "date": result.get("Date", ""),
                "commit": result.get("Commit", ""),
                "fix_guidance": self._get_fix_guidance(result),
                "references": ["https://github.com/zricethezav/gitleaks"],
                "raw_output": self._sanitize_output(result)
            }
            
            findings.append(finding)
        
        return findings
    
    def _get_secret_title(self, result: Dict[str, Any]) -> str:
        """
        Generate a title for the secret finding.
        
        Args:
            result: Gitleaks result
            
        Returns:
            Title string
        """
        rule_id = result.get("RuleID", "").lower()
        secret_type = self._determine_secret_type(result)
        
        return f"{secret_type} detected in {os.path.basename(result.get('File', 'unknown'))}"
    
    def _determine_severity(self, result: Dict[str, Any]) -> str:
        """
        Determine severity based on secret type and context.
        
        Args:
            result: Gitleaks result
            
        Returns:
            Severity level
        """
        rule_id = result.get("RuleID", "").lower()
        
        # Critical severity for production credentials
        critical_patterns = [
            "aws", "azure", "gcp", "private_key", "stripe",
            "database", "jwt", "oauth", "service_account"
        ]
        
        # High severity for API keys and tokens
        high_patterns = [
            "api_key", "token", "secret", "password", "auth",
            "github", "gitlab", "slack", "discord"
        ]
        
        # Check patterns
        for pattern in critical_patterns:
            if pattern in rule_id:
                return "critical"
        
        for pattern in high_patterns:
            if pattern in rule_id:
                return "high"
        
        # Check entropy for generic secrets
        entropy = result.get("Entropy", 0)
        if entropy > 4.5:
            return "high"
        elif entropy > 3.5:
            return "medium"
        
        return "medium"
    
    def _determine_secret_type(self, result: Dict[str, Any]) -> str:
        """
        Determine the type of secret detected.
        
        Args:
            result: Gitleaks result
            
        Returns:
            Secret type string
        """
        rule_id = result.get("RuleID", "").lower()
        description = result.get("Description", "").lower()
        
        # Check known patterns
        for pattern, name in self.secret_patterns.items():
            if pattern in rule_id or pattern in description:
                return name
        
        # Fallback to rule ID or generic
        if rule_id:
            return rule_id.replace("_", " ").title()
        
        return "Generic Secret"
    
    def _sanitize_secret(self, secret: str) -> str:
        """
        Sanitize secret value to avoid exposing sensitive data.
        
        Args:
            secret: Raw secret value
            
        Returns:
            Sanitized secret string
        """
        if not secret:
            return ""
        
        # Keep first and last few characters, mask the middle
        if len(secret) <= 8:
            return "*" * len(secret)
        elif len(secret) <= 20:
            return secret[:3] + "*" * (len(secret) - 6) + secret[-3:]
        else:
            return secret[:4] + "*" * 12 + secret[-4:]
    
    def _sanitize_output(self, result: Dict[str, Any]) -> Dict[str, Any]:
        """
        Sanitize the raw output to remove actual secret values.
        
        Args:
            result: Raw result
            
        Returns:
            Sanitized result
        """
        sanitized = result.copy()
        
        # Sanitize secret fields
        if "Secret" in sanitized:
            sanitized["Secret"] = self._sanitize_secret(sanitized["Secret"])
        if "Match" in sanitized:
            sanitized["Match"] = self._sanitize_secret(sanitized["Match"])
        
        return sanitized
    
    def _get_fix_guidance(self, result: Dict[str, Any]) -> str:
        """
        Generate fix guidance for the secret finding.
        
        Args:
            result: Gitleaks result
            
        Returns:
            Fix guidance string
        """
        secret_type = self._determine_secret_type(result)
        file_path = result.get("File", "")
        
        guidance = [
            f"1. Remove the {secret_type} from the source code immediately.",
            "2. Rotate/revoke the exposed credential if it was ever committed.",
            "3. Use environment variables or a secure secret management system.",
            "4. Add the file to .gitignore if it contains secrets.",
            "5. Consider using git-secrets or pre-commit hooks to prevent future leaks."
        ]
        
        # Add specific guidance based on secret type
        if "aws" in secret_type.lower():
            guidance.insert(2, "   - Rotate AWS credentials in IAM console")
        elif "github" in secret_type.lower():
            guidance.insert(2, "   - Revoke token in GitHub Settings > Developer settings")
        elif "api_key" in secret_type.lower():
            guidance.insert(2, "   - Regenerate API key in the service's dashboard")
        
        return "\n".join(guidance)