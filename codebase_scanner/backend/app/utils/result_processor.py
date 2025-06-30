"""
Result processing utilities for normalizing and deduplicating scan findings.
"""

import hashlib
import logging
import os
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
import re

from src.utils.cvss import CVSSCalculator, SecurityMetrics

logger = logging.getLogger(__name__)


class ResultProcessor:
    """
    Processes and normalizes scan results from different scanners.
    
    This class handles:
    - Result normalization
    - Deduplication
    - Severity scoring
    - Priority calculation
    - Result enrichment
    """
    
    # Severity weights for scoring
    SEVERITY_WEIGHTS = {
        "critical": 10,
        "high": 7,
        "medium": 4,
        "low": 2,
        "info": 1
    }
    
    # Category priority for fixing
    CATEGORY_PRIORITY = {
        "injection": 1,
        "authentication": 1,
        "secrets": 1,
        "vulnerable-dependency": 2,
        "cryptography": 2,
        "deserialization": 2,
        "path-traversal": 3,
        "ssrf": 3,
        "security-misconfiguration": 4,
        "sensitive-data": 4,
        "other": 5
    }
    
    def __init__(self):
        """Initialize result processor."""
        self.cwe_database = self._load_cwe_database()
    
    async def process_results(
        self,
        scan_results: Dict[str, List[Dict[str, Any]]],
        base_path: str
    ) -> List[Dict[str, Any]]:
        """
        Process and normalize scan results from multiple scanners.
        
        Args:
            scan_results: Dict mapping scanner names to their results
            base_path: Base path for resolving relative file paths
            
        Returns:
            List of processed and deduplicated findings
        """
        all_findings = []
        
        # Process results from each scanner
        for scanner_name, findings in scan_results.items():
            for finding in findings:
                processed = self._normalize_finding(finding, scanner_name, base_path)
                if processed:
                    all_findings.append(processed)
        
        # Deduplicate findings
        deduplicated = self._deduplicate_findings(all_findings)
        
        # Calculate fix priority
        prioritized = self._calculate_priorities(deduplicated)
        
        # Sort by priority
        prioritized.sort(key=lambda x: (x.get("fix_priority", 999), -self.SEVERITY_WEIGHTS.get(x.get("severity", "info"), 0)))
        
        return prioritized
    
    def _normalize_finding(
        self,
        finding: Dict[str, Any],
        scanner_name: str,
        base_path: str
    ) -> Optional[Dict[str, Any]]:
        """
        Normalize a finding to standard format.
        
        Args:
            finding: Raw finding from scanner
            scanner_name: Name of the scanner
            base_path: Base path for file resolution
            
        Returns:
            Normalized finding or None if invalid
        """
        try:
            # Ensure required fields
            normalized = {
                "scanner": scanner_name,
                "rule_id": finding.get("rule_id", "unknown"),
                "title": finding.get("title", "Security Issue"),
                "description": finding.get("description", ""),
                "severity": self._normalize_severity(finding.get("severity", "info")),
                "category": finding.get("category", "other"),
                "confidence": finding.get("confidence", "MEDIUM"),
            }
            
            # Normalize file path
            file_path = finding.get("file_path", "")
            if file_path:
                normalized["file_path"] = self._normalize_path(file_path, base_path)
            else:
                normalized["file_path"] = ""
            
            # Location information
            normalized["line_start"] = max(0, int(finding.get("line_start", 0)))
            normalized["line_end"] = max(normalized["line_start"], int(finding.get("line_end", normalized["line_start"])))
            normalized["column_start"] = max(0, int(finding.get("column_start", 0)))
            normalized["column_end"] = max(normalized["column_start"], int(finding.get("column_end", normalized["column_start"])))
            
            # Additional information
            normalized["code_snippet"] = finding.get("code_snippet", "")
            normalized["fix_guidance"] = finding.get("fix_guidance", "")
            normalized["references"] = finding.get("references", [])
            normalized["cwe"] = finding.get("cwe")
            normalized["owasp"] = finding.get("owasp")
            
            # Scanner-specific fields
            if scanner_name == "safety":
                normalized["package_name"] = finding.get("package_name")
                normalized["installed_version"] = finding.get("installed_version")
                normalized["vulnerability_id"] = finding.get("vulnerability_id")
                normalized["cvss_score"] = finding.get("cvss_score", 0)
            
            if scanner_name == "gitleaks":
                normalized["secret_type"] = finding.get("secret_type")
                normalized["match"] = finding.get("match")
                normalized["entropy"] = finding.get("entropy", 0)
                normalized["commit"] = finding.get("commit")
            
            if scanner_name == "bandit":
                normalized["test_id"] = finding.get("test_id")
            
            # Generate unique fingerprint
            normalized["fingerprint"] = self._generate_fingerprint(normalized)
            
            # Calculate risk score
            normalized["risk_score"] = self._calculate_risk_score(normalized)
            
            # Calculate CVSS score if not already present
            if "cvss" not in normalized or not normalized.get("cvss"):
                cvss_data = CVSSCalculator.estimate_cvss_from_vulnerability(normalized)
                normalized["cvss"] = cvss_data
                normalized["cvss_score"] = cvss_data["base_score"]
                normalized["cvss_vector"] = cvss_data["vector"]
            
            return normalized
            
        except Exception as e:
            logger.error(f"Failed to normalize finding: {e}")
            return None
    
    def _normalize_severity(self, severity: str) -> str:
        """
        Normalize severity to standard levels.
        
        Args:
            severity: Raw severity string
            
        Returns:
            Normalized severity
        """
        severity_lower = severity.lower()
        
        # Map various severity names to standard levels
        if severity_lower in ["critical", "blocker"]:
            return "critical"
        elif severity_lower in ["high", "major", "error"]:
            return "high"
        elif severity_lower in ["medium", "moderate", "warning"]:
            return "medium"
        elif severity_lower in ["low", "minor", "note"]:
            return "low"
        else:
            return "info"
    
    def _normalize_path(self, file_path: str, base_path: str) -> str:
        """
        Normalize file path to be relative to scan root.
        
        Args:
            file_path: Original file path
            base_path: Base path of scan
            
        Returns:
            Normalized relative path
        """
        try:
            # Convert to Path objects
            path = Path(file_path)
            base = Path(base_path)
            
            # Make relative if possible
            if path.is_absolute():
                try:
                    return str(path.relative_to(base))
                except ValueError:
                    # Not relative to base, try to extract meaningful part
                    parts = path.parts
                    if "extracted" in parts:
                        idx = parts.index("extracted")
                        return str(Path(*parts[idx+1:]))
            
            return str(path)
            
        except Exception:
            return file_path
    
    def _generate_fingerprint(self, finding: Dict[str, Any]) -> str:
        """
        Generate unique fingerprint for a finding.
        
        Args:
            finding: Normalized finding
            
        Returns:
            SHA256 fingerprint
        """
        # Create fingerprint from key fields
        fingerprint_data = {
            "rule_id": finding.get("rule_id"),
            "file_path": finding.get("file_path"),
            "line_start": finding.get("line_start"),
            "category": finding.get("category"),
            "title": finding.get("title")
        }
        
        # Add scanner-specific fields
        if finding.get("package_name"):
            fingerprint_data["package_name"] = finding["package_name"]
            fingerprint_data["vulnerability_id"] = finding.get("vulnerability_id")
        
        # Create stable string representation
        fingerprint_str = "|".join(str(v) for v in fingerprint_data.values())
        
        return hashlib.sha256(fingerprint_str.encode()).hexdigest()
    
    def _deduplicate_findings(
        self,
        findings: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Deduplicate findings based on fingerprints and similarity.
        
        Args:
            findings: List of normalized findings
            
        Returns:
            Deduplicated list of findings
        """
        # Group by fingerprint
        fingerprint_groups = defaultdict(list)
        for finding in findings:
            fingerprint_groups[finding["fingerprint"]].append(finding)
        
        # For each group, merge similar findings
        deduplicated = []
        for fingerprint, group in fingerprint_groups.items():
            if len(group) == 1:
                deduplicated.append(group[0])
            else:
                # Merge findings from different scanners
                merged = self._merge_findings(group)
                deduplicated.append(merged)
        
        # Additional deduplication based on similarity
        final_results = []
        seen_similar = set()
        
        for finding in deduplicated:
            similarity_key = self._get_similarity_key(finding)
            if similarity_key not in seen_similar:
                seen_similar.add(similarity_key)
                final_results.append(finding)
            else:
                # Check if this is actually different enough
                if self._is_sufficiently_different(finding, final_results):
                    final_results.append(finding)
        
        return final_results
    
    def _merge_findings(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Merge multiple similar findings into one.
        
        Args:
            findings: List of similar findings
            
        Returns:
            Merged finding
        """
        # Start with the highest severity finding
        findings.sort(key=lambda x: -self.SEVERITY_WEIGHTS.get(x.get("severity", "info"), 0))
        merged = findings[0].copy()
        
        # Collect all scanners that found this issue
        scanners = list(set(f["scanner"] for f in findings))
        merged["scanner"] = scanners[0] if len(scanners) == 1 else "multiple"
        merged["detected_by"] = scanners
        
        # Use highest severity and confidence
        for finding in findings[1:]:
            if self.SEVERITY_WEIGHTS.get(finding["severity"], 0) > self.SEVERITY_WEIGHTS.get(merged["severity"], 0):
                merged["severity"] = finding["severity"]
            
            # Merge references
            merged["references"].extend(finding.get("references", []))
            
            # Merge fix guidance
            if finding.get("fix_guidance") and len(finding["fix_guidance"]) > len(merged.get("fix_guidance", "")):
                merged["fix_guidance"] = finding["fix_guidance"]
        
        # Remove duplicate references
        merged["references"] = list(set(merged["references"]))
        
        return merged
    
    def _get_similarity_key(self, finding: Dict[str, Any]) -> str:
        """
        Generate a key for similarity comparison.
        
        Args:
            finding: Finding to generate key for
            
        Returns:
            Similarity key
        """
        # Less strict than fingerprint - allows for minor variations
        return f"{finding['category']}|{finding['file_path']}|{finding['line_start'] // 10}"
    
    def _is_sufficiently_different(
        self,
        finding: Dict[str, Any],
        existing_findings: List[Dict[str, Any]]
    ) -> bool:
        """
        Check if finding is sufficiently different from existing ones.
        
        Args:
            finding: Finding to check
            existing_findings: List of already accepted findings
            
        Returns:
            True if sufficiently different
        """
        for existing in existing_findings:
            # Same file and nearby location
            if (existing["file_path"] == finding["file_path"] and
                abs(existing["line_start"] - finding["line_start"]) < 5 and
                existing["category"] == finding["category"]):
                return False
        
        return True
    
    def _calculate_risk_score(self, finding: Dict[str, Any]) -> int:
        """
        Calculate risk score for a finding.
        
        Args:
            finding: Normalized finding
            
        Returns:
            Risk score (0-100)
        """
        score = 0
        
        # Base score from severity
        score += self.SEVERITY_WEIGHTS.get(finding["severity"], 0) * 8
        
        # Adjust based on confidence
        confidence = finding.get("confidence", "MEDIUM").upper()
        if confidence == "HIGH":
            score *= 1.2
        elif confidence == "LOW":
            score *= 0.8
        
        # Category-based adjustments
        category = finding["category"]
        if category in ["injection", "authentication", "secrets"]:
            score *= 1.5
        elif category in ["vulnerable-dependency"]:
            # Use CVSS score if available
            cvss = finding.get("cvss_score", 0)
            if cvss > 0:
                score = max(score, cvss * 10)
        
        # Cap at 100
        return min(int(score), 100)
    
    def _calculate_priorities(
        self,
        findings: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Calculate fix priorities for findings.
        
        Args:
            findings: List of findings
            
        Returns:
            Findings with fix_priority field
        """
        for finding in findings:
            # Priority based on severity and category
            severity_priority = 6 - self.SEVERITY_WEIGHTS.get(finding["severity"], 0)
            category_priority = self.CATEGORY_PRIORITY.get(finding["category"], 5)
            
            # Calculate combined priority (lower is higher priority)
            finding["fix_priority"] = severity_priority + category_priority
            
            # Boost priority for certain conditions
            if finding.get("scanner") == "gitleaks":
                finding["fix_priority"] -= 2  # Secrets are high priority
            
            if finding.get("scanner") == "safety" and finding.get("cvss_score", 0) >= 9:
                finding["fix_priority"] -= 1  # Critical vulnerabilities
            
            # Ensure priority is positive
            finding["fix_priority"] = max(1, finding["fix_priority"])
        
        return findings
    
    def _load_cwe_database(self) -> Dict[str, Dict[str, Any]]:
        """
        Load CWE database for enrichment.
        
        Returns:
            Dict mapping CWE IDs to information
        """
        # Simplified CWE database - in production, load from file
        return {
            "CWE-79": {
                "name": "Cross-site Scripting (XSS)",
                "description": "Improper neutralization of input during web page generation"
            },
            "CWE-89": {
                "name": "SQL Injection",
                "description": "Improper neutralization of special elements in SQL commands"
            },
            "CWE-78": {
                "name": "OS Command Injection",
                "description": "Improper neutralization of special elements in OS commands"
            },
            "CWE-22": {
                "name": "Path Traversal",
                "description": "Improper limitation of a pathname to a restricted directory"
            },
            "CWE-798": {
                "name": "Hardcoded Credentials",
                "description": "Use of hard-coded credentials"
            },
            "CWE-327": {
                "name": "Broken Cryptography",
                "description": "Use of a broken or risky cryptographic algorithm"
            },
            "CWE-502": {
                "name": "Deserialization of Untrusted Data",
                "description": "Deserialization of untrusted data"
            }
        }
    
    def calculate_scan_metrics(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Calculate comprehensive security metrics for scan results.
        
        Args:
            findings: List of scan findings
            
        Returns:
            Dictionary containing security metrics
        """
        # Basic metrics
        metrics = SecurityMetrics.calculate_security_score(findings)
        
        # Add CVSS distribution
        cvss_distribution = {
            "none": 0,
            "low": 0,
            "medium": 0,
            "high": 0,
            "critical": 0
        }
        
        cvss_scores = []
        for finding in findings:
            if "cvss_score" in finding:
                score = finding["cvss_score"]
                cvss_scores.append(score)
                severity = CVSSCalculator.get_severity(score)
                cvss_distribution[severity.lower()] += 1
        
        metrics["cvss_distribution"] = cvss_distribution
        
        if cvss_scores:
            metrics["cvss_statistics"] = {
                "average": round(sum(cvss_scores) / len(cvss_scores), 1),
                "max": max(cvss_scores),
                "min": min(cvss_scores)
            }
        
        # Category distribution
        category_distribution = {}
        for finding in findings:
            category = finding.get("category", "other")
            category_distribution[category] = category_distribution.get(category, 0) + 1
        
        metrics["category_distribution"] = category_distribution
        
        # Scanner distribution
        scanner_distribution = {}
        for finding in findings:
            scanner = finding.get("scanner", "unknown")
            scanner_distribution[scanner] = scanner_distribution.get(scanner, 0) + 1
        
        metrics["scanner_distribution"] = scanner_distribution
        
        return metrics