"""
Tests for Claude AI service integration.
"""
import pytest
from unittest.mock import Mock, AsyncMock, patch
import json
from src.services.claude_service import ClaudeSecurityAnalyzer

class TestClaudeSecurityAnalyzer:
    """Test Claude AI security analysis service."""
    
    @pytest.fixture
    def analyzer(self, mock_claude, mock_redis):
        """Create analyzer instance with mocks."""
        with patch('anthropic.Anthropic', return_value=mock_claude):
            analyzer = ClaudeSecurityAnalyzer(
                api_key="test-key",
                redis_client=mock_redis
            )
            return analyzer
    
    @pytest.mark.asyncio
    async def test_analyze_vulnerability_basic(self, analyzer, sample_vulnerability):
        """Test basic vulnerability analysis."""
        result = await analyzer.analyze_vulnerability(sample_vulnerability)
        
        assert "vulnerability_analysis" in result
        assert "fix_recommendations" in result
        assert "risk_assessment" in result
        assert "references" in result
    
    @pytest.mark.asyncio
    async def test_analyze_vulnerability_with_cache(self, analyzer, sample_vulnerability, mock_redis):
        """Test vulnerability analysis with caching."""
        # Set up cache hit
        cached_result = {
            "vulnerability_analysis": "Cached analysis",
            "cached": True
        }
        mock_redis.get.return_value = json.dumps(cached_result)
        
        result = await analyzer.analyze_vulnerability(sample_vulnerability)
        
        assert result["cached"] is True
        assert result["vulnerability_analysis"] == "Cached analysis"
        mock_redis.get.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_analyze_scan_results(self, analyzer, sample_scan_results):
        """Test full scan results analysis."""
        result = await analyzer.analyze_scan_results(
            scan_results=sample_scan_results,
            project_context={
                "name": "Test Project",
                "language": "python"
            }
        )
        
        assert "summary" in result
        assert "critical_findings" in result
        assert "security_recommendations" in result
        assert "risk_score" in result
    
    @pytest.mark.asyncio
    async def test_get_compliance_recommendations(self, analyzer, sample_scan_results):
        """Test compliance recommendations generation."""
        result = await analyzer.get_compliance_recommendations(
            scan_results=sample_scan_results,
            compliance_frameworks=["OWASP", "PCI-DSS"]
        )
        
        assert "compliance_gaps" in result
        assert "recommendations" in result
        assert "priority_actions" in result
    
    @pytest.mark.asyncio
    async def test_generate_fix_code_sql_injection(self, analyzer):
        """Test fix code generation for SQL injection."""
        vulnerability = {
            "vulnerability_type": "sql injection",
            "code_snippet": 'query = f"SELECT * FROM users WHERE id = {user_id}"',
            "language": "python"
        }
        
        result = await analyzer.generate_fix_code(
            vulnerability=vulnerability,
            context={"framework": "flask"}
        )
        
        assert "fixed_code" in result
        assert "explanation" in result
        assert "parameterized" in result["explanation"].lower() or "prepared" in result["explanation"].lower()
    
    @pytest.mark.asyncio
    async def test_error_handling(self, analyzer, mock_claude):
        """Test error handling in Claude service."""
        # Simulate API error
        mock_claude.messages.create.side_effect = Exception("API Error")
        
        vulnerability = {"title": "Test", "severity": "high"}
        result = await analyzer.analyze_vulnerability(vulnerability)
        
        # Should return graceful error response
        assert "error" in result or "vulnerability_analysis" in result
    
    def test_cache_key_generation(self, analyzer, sample_vulnerability):
        """Test cache key generation consistency."""
        key1 = analyzer._generate_cache_key("analyze", sample_vulnerability)
        key2 = analyzer._generate_cache_key("analyze", sample_vulnerability)
        
        assert key1 == key2
        assert key1.startswith("claude:analyze:")
    
    @pytest.mark.asyncio
    async def test_batch_analysis(self, analyzer):
        """Test batch vulnerability analysis."""
        vulnerabilities = [
            {"title": "SQL Injection", "severity": "critical"},
            {"title": "XSS", "severity": "high"},
            {"title": "Weak Crypto", "severity": "medium"}
        ]
        
        # Mock batch responses
        analyzer.client.messages.create.side_effect = [
            Mock(content=[Mock(text="Analysis 1")]),
            Mock(content=[Mock(text="Analysis 2")]),
            Mock(content=[Mock(text="Analysis 3")])
        ]
        
        results = []
        for vuln in vulnerabilities:
            result = await analyzer.analyze_vulnerability(vuln)
            results.append(result)
        
        assert len(results) == 3
        assert all("vulnerability_analysis" in r for r in results)