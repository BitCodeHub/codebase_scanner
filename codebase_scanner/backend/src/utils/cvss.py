"""
CVSS (Common Vulnerability Scoring System) calculator and utilities.
"""
from typing import Dict, Any, Tuple
from enum import Enum
import math

class CVSSMetric(Enum):
    """CVSS v3.1 metrics"""
    # Base Metrics
    ATTACK_VECTOR = "AV"
    ATTACK_COMPLEXITY = "AC"
    PRIVILEGES_REQUIRED = "PR"
    USER_INTERACTION = "UI"
    SCOPE = "S"
    CONFIDENTIALITY = "C"
    INTEGRITY = "I"
    AVAILABILITY = "A"

class CVSSCalculator:
    """Calculate CVSS v3.1 scores for vulnerabilities."""
    
    # CVSS v3.1 weights
    WEIGHTS = {
        "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
        "AC": {"L": 0.77, "H": 0.44},
        "PR": {
            "U": {"N": 0.85, "L": 0.62, "H": 0.27},
            "C": {"N": 0.85, "L": 0.68, "H": 0.5}
        },
        "UI": {"N": 0.85, "R": 0.62},
        "S": {"U": 1.0, "C": 1.0},
        "C": {"N": 0, "L": 0.22, "H": 0.56},
        "I": {"N": 0, "L": 0.22, "H": 0.56},
        "A": {"N": 0, "L": 0.22, "H": 0.56}
    }
    
    @classmethod
    def calculate_base_score(cls, metrics: Dict[str, str]) -> float:
        """
        Calculate CVSS base score from metrics.
        
        Args:
            metrics: Dictionary of CVSS metrics
            
        Returns:
            Base score (0.0 - 10.0)
        """
        # Extract metrics
        av = metrics.get("AV", "N")
        ac = metrics.get("AC", "L")
        pr = metrics.get("PR", "N")
        ui = metrics.get("UI", "N")
        s = metrics.get("S", "U")
        c = metrics.get("C", "N")
        i = metrics.get("I", "N")
        a = metrics.get("A", "N")
        
        # Calculate ISS (Impact Sub Score)
        iss_base = 1 - ((1 - cls.WEIGHTS["C"][c]) * 
                       (1 - cls.WEIGHTS["I"][i]) * 
                       (1 - cls.WEIGHTS["A"][a]))
        
        # Calculate Impact
        if s == "U":
            impact = 6.42 * iss_base
        else:
            impact = 7.52 * (iss_base - 0.029) - 3.25 * pow(iss_base - 0.02, 15)
        
        # Calculate Exploitability
        pr_weight = cls.WEIGHTS["PR"]["U" if s == "U" else "C"][pr]
        exploitability = 8.22 * cls.WEIGHTS["AV"][av] * \
                        cls.WEIGHTS["AC"][ac] * \
                        pr_weight * \
                        cls.WEIGHTS["UI"][ui]
        
        # Calculate base score
        if impact <= 0:
            return 0.0
        
        if s == "U":
            base_score = min(impact + exploitability, 10)
        else:
            base_score = min(1.08 * (impact + exploitability), 10)
        
        # Round to one decimal place
        return round(base_score, 1)
    
    @classmethod
    def get_severity(cls, score: float) -> str:
        """Get severity rating from CVSS score."""
        if score == 0:
            return "None"
        elif score < 4.0:
            return "Low"
        elif score < 7.0:
            return "Medium"
        elif score < 9.0:
            return "High"
        else:
            return "Critical"
    
    @classmethod
    def generate_vector_string(cls, metrics: Dict[str, str]) -> str:
        """Generate CVSS v3.1 vector string."""
        vector_parts = ["CVSS:3.1"]
        
        for metric in ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]:
            if metric in metrics:
                vector_parts.append(f"{metric}:{metrics[metric]}")
        
        return "/".join(vector_parts)
    
    @classmethod
    def estimate_cvss_from_vulnerability(cls, vulnerability: Dict[str, Any]) -> Dict[str, Any]:
        """
        Estimate CVSS metrics based on vulnerability type and context.
        
        Args:
            vulnerability: Vulnerability details
            
        Returns:
            Dictionary with CVSS score, vector, and metrics
        """
        vuln_type = vulnerability.get("vulnerability_type", "").lower()
        severity = vulnerability.get("severity", "medium").lower()
        
        # Default metrics
        metrics = {
            "AV": "N",  # Network
            "AC": "L",  # Low
            "PR": "N",  # None
            "UI": "N",  # None
            "S": "U",   # Unchanged
            "C": "N",   # None
            "I": "N",   # None
            "A": "N"    # None
        }
        
        # Estimate based on vulnerability type
        if "sql injection" in vuln_type:
            metrics.update({"C": "H", "I": "H", "A": "L", "AC": "L"})
        elif "xss" in vuln_type or "cross-site scripting" in vuln_type:
            metrics.update({"C": "L", "I": "L", "UI": "R", "PR": "N"})
        elif "command injection" in vuln_type or "os command" in vuln_type:
            metrics.update({"C": "H", "I": "H", "A": "H", "AC": "L"})
        elif "path traversal" in vuln_type or "directory traversal" in vuln_type:
            metrics.update({"C": "H", "I": "L", "AV": "N", "PR": "L"})
        elif "hardcoded" in vuln_type or "credential" in vuln_type:
            metrics.update({"C": "H", "I": "L", "AC": "L", "AV": "L"})
        elif "deserialization" in vuln_type:
            metrics.update({"C": "H", "I": "H", "A": "H", "AC": "L"})
        elif "buffer overflow" in vuln_type:
            metrics.update({"C": "H", "I": "H", "A": "H", "AC": "H"})
        elif "race condition" in vuln_type:
            metrics.update({"I": "H", "A": "L", "AC": "H"})
        elif "weak crypto" in vuln_type or "weak encryption" in vuln_type:
            metrics.update({"C": "H", "AC": "H", "PR": "N"})
        else:
            # Generic based on severity
            if severity == "critical":
                metrics.update({"C": "H", "I": "H", "A": "H"})
            elif severity == "high":
                metrics.update({"C": "H", "I": "L", "A": "L"})
            elif severity == "medium":
                metrics.update({"C": "L", "I": "L", "A": "N"})
            else:  # low
                metrics.update({"C": "L", "I": "N", "A": "N"})
        
        # Calculate score
        base_score = cls.calculate_base_score(metrics)
        vector = cls.generate_vector_string(metrics)
        
        return {
            "base_score": base_score,
            "severity": cls.get_severity(base_score),
            "vector": vector,
            "metrics": metrics,
            "version": "3.1"
        }

class SecurityMetrics:
    """Calculate security metrics for scan results."""
    
    @staticmethod
    def calculate_security_score(vulnerabilities: list) -> Dict[str, Any]:
        """
        Calculate overall security score based on vulnerabilities.
        
        Returns score from 0-100 where 100 is most secure.
        """
        if not vulnerabilities:
            return {
                "score": 100,
                "grade": "A+",
                "risk_level": "Very Low"
            }
        
        # Weight factors for different severities
        weights = {
            "critical": 40,
            "high": 20,
            "medium": 10,
            "low": 5,
            "info": 1
        }
        
        # Count vulnerabilities by severity
        severity_counts = {}
        total_weight = 0
        
        for vuln in vulnerabilities:
            severity = vuln.get("severity", "medium").lower()
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            total_weight += weights.get(severity, 5)
        
        # Calculate score (inverse of risk)
        # Max possible weight for reasonable calculation
        max_weight = len(vulnerabilities) * weights["critical"]
        risk_percentage = min((total_weight / max_weight) * 100, 100)
        score = max(0, 100 - risk_percentage)
        
        # Determine grade
        if score >= 90:
            grade = "A+"
        elif score >= 80:
            grade = "A"
        elif score >= 70:
            grade = "B"
        elif score >= 60:
            grade = "C"
        elif score >= 50:
            grade = "D"
        else:
            grade = "F"
        
        # Risk level
        if score >= 90:
            risk_level = "Very Low"
        elif score >= 70:
            risk_level = "Low"
        elif score >= 50:
            risk_level = "Medium"
        elif score >= 30:
            risk_level = "High"
        else:
            risk_level = "Critical"
        
        return {
            "score": round(score, 1),
            "grade": grade,
            "risk_level": risk_level,
            "severity_distribution": severity_counts,
            "total_vulnerabilities": len(vulnerabilities),
            "weighted_risk": round(risk_percentage, 1)
        }
    
    @staticmethod
    def calculate_metrics_trends(scans: list) -> Dict[str, Any]:
        """Calculate security metrics trends over multiple scans."""
        if not scans:
            return {}
        
        trends = {
            "scores": [],
            "vulnerability_counts": [],
            "severity_trends": {
                "critical": [],
                "high": [],
                "medium": [],
                "low": []
            },
            "improvement_rate": 0
        }
        
        for scan in sorted(scans, key=lambda x: x.get("created_at", "")):
            results = scan.get("results", [])
            metrics = SecurityMetrics.calculate_security_score(results)
            
            trends["scores"].append({
                "date": scan.get("created_at"),
                "score": metrics["score"]
            })
            
            trends["vulnerability_counts"].append({
                "date": scan.get("created_at"),
                "count": len(results)
            })
            
            # Track severity trends
            for severity in ["critical", "high", "medium", "low"]:
                count = metrics["severity_distribution"].get(severity, 0)
                trends["severity_trends"][severity].append({
                    "date": scan.get("created_at"),
                    "count": count
                })
        
        # Calculate improvement rate
        if len(trends["scores"]) >= 2:
            first_score = trends["scores"][0]["score"]
            last_score = trends["scores"][-1]["score"]
            trends["improvement_rate"] = round(last_score - first_score, 1)
        
        return trends