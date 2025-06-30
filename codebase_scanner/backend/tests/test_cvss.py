"""
Tests for CVSS calculator and security metrics.
"""
import pytest
from src.utils.cvss import CVSSCalculator, SecurityMetrics

class TestCVSSCalculator:
    """Test CVSS calculation functionality."""
    
    def test_calculate_base_score_critical(self):
        """Test CVSS calculation for critical vulnerability."""
        metrics = {
            "AV": "N",  # Network
            "AC": "L",  # Low complexity
            "PR": "N",  # No privileges
            "UI": "N",  # No user interaction
            "S": "C",   # Changed scope
            "C": "H",   # High confidentiality impact
            "I": "H",   # High integrity impact
            "A": "H"    # High availability impact
        }
        
        score = CVSSCalculator.calculate_base_score(metrics)
        assert score == 10.0
        assert CVSSCalculator.get_severity(score) == "Critical"
    
    def test_calculate_base_score_medium(self):
        """Test CVSS calculation for medium vulnerability."""
        metrics = {
            "AV": "N",
            "AC": "L",
            "PR": "L",
            "UI": "R",
            "S": "U",
            "C": "L",
            "I": "L",
            "A": "N"
        }
        
        score = CVSSCalculator.calculate_base_score(metrics)
        assert 4.0 <= score < 7.0
        assert CVSSCalculator.get_severity(score) == "Medium"
    
    def test_generate_vector_string(self):
        """Test CVSS vector string generation."""
        metrics = {
            "AV": "N",
            "AC": "L",
            "PR": "N",
            "UI": "N",
            "S": "U",
            "C": "H",
            "I": "H",
            "A": "H"
        }
        
        vector = CVSSCalculator.generate_vector_string(metrics)
        assert vector == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    
    def test_estimate_cvss_sql_injection(self):
        """Test CVSS estimation for SQL injection."""
        vulnerability = {
            "vulnerability_type": "sql injection",
            "severity": "critical"
        }
        
        result = CVSSCalculator.estimate_cvss_from_vulnerability(vulnerability)
        assert result["base_score"] >= 7.0
        assert result["metrics"]["C"] == "H"
        assert result["metrics"]["I"] == "H"
        assert "vector" in result
    
    def test_estimate_cvss_xss(self):
        """Test CVSS estimation for XSS."""
        vulnerability = {
            "vulnerability_type": "cross-site scripting",
            "severity": "medium"
        }
        
        result = CVSSCalculator.estimate_cvss_from_vulnerability(vulnerability)
        assert result["metrics"]["UI"] == "R"  # Requires user interaction
        assert result["metrics"]["C"] == "L"
        assert result["metrics"]["I"] == "L"
    
    def test_estimate_cvss_hardcoded_credentials(self):
        """Test CVSS estimation for hardcoded credentials."""
        vulnerability = {
            "vulnerability_type": "hardcoded password",
            "severity": "high"
        }
        
        result = CVSSCalculator.estimate_cvss_from_vulnerability(vulnerability)
        assert result["metrics"]["C"] == "H"
        assert result["metrics"]["AV"] == "L"  # Local access

class TestSecurityMetrics:
    """Test security metrics calculation."""
    
    def test_calculate_security_score_no_vulnerabilities(self):
        """Test security score with no vulnerabilities."""
        result = SecurityMetrics.calculate_security_score([])
        assert result["score"] == 100
        assert result["grade"] == "A+"
        assert result["risk_level"] == "Very Low"
    
    def test_calculate_security_score_critical_vulnerabilities(self):
        """Test security score with critical vulnerabilities."""
        vulnerabilities = [
            {"severity": "critical"},
            {"severity": "critical"},
            {"severity": "high"}
        ]
        
        result = SecurityMetrics.calculate_security_score(vulnerabilities)
        assert result["score"] < 50
        assert result["grade"] in ["F", "D"]
        assert result["risk_level"] in ["Critical", "High"]
        assert result["total_vulnerabilities"] == 3
    
    def test_calculate_security_score_mixed_severities(self):
        """Test security score with mixed severity vulnerabilities."""
        vulnerabilities = [
            {"severity": "low"},
            {"severity": "medium"},
            {"severity": "medium"},
            {"severity": "high"}
        ]
        
        result = SecurityMetrics.calculate_security_score(vulnerabilities)
        assert 50 <= result["score"] < 80
        assert result["severity_distribution"]["medium"] == 2
        assert result["severity_distribution"]["high"] == 1
        assert result["severity_distribution"]["low"] == 1
    
    def test_calculate_metrics_trends(self):
        """Test security metrics trends calculation."""
        scans = [
            {
                "created_at": "2024-01-01",
                "results": [
                    {"severity": "critical"},
                    {"severity": "high"},
                    {"severity": "high"}
                ]
            },
            {
                "created_at": "2024-01-15",
                "results": [
                    {"severity": "high"},
                    {"severity": "medium"}
                ]
            },
            {
                "created_at": "2024-02-01",
                "results": [
                    {"severity": "low"}
                ]
            }
        ]
        
        trends = SecurityMetrics.calculate_metrics_trends(scans)
        
        assert len(trends["scores"]) == 3
        assert len(trends["vulnerability_counts"]) == 3
        assert trends["vulnerability_counts"][0]["count"] == 3
        assert trends["vulnerability_counts"][2]["count"] == 1
        assert trends["improvement_rate"] > 0  # Score improved