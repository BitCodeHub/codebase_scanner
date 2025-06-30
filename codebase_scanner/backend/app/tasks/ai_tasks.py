"""
Celery tasks for AI analysis with caching.
"""
import json
import hashlib
from datetime import datetime, timedelta
from typing import Dict, Any, Optional

from app.celery_app import celery_app
from src.services.claude_service import ClaudeSecurityAnalyzer
from src.database import get_supabase_client, get_redis_client
from src.utils.logging import get_logger

logger = get_logger(__name__)

# Cache TTL in seconds (24 hours)
CACHE_TTL = 86400

@celery_app.task(name="app.tasks.ai_tasks.analyze_vulnerability")
def analyze_vulnerability_task(vulnerability: Dict[str, Any], use_cache: bool = True) -> Dict[str, Any]:
    """
    Analyze a vulnerability using Claude AI with caching.
    
    Args:
        vulnerability: Vulnerability data to analyze
        use_cache: Whether to use cached results
        
    Returns:
        AI analysis results
    """
    try:
        # Generate cache key
        cache_key = _generate_cache_key("vuln_analysis", vulnerability)
        
        # Check cache if enabled
        if use_cache:
            cached_result = _get_cached_result(cache_key)
            if cached_result:
                logger.info(f"Cache hit for vulnerability analysis: {cache_key}")
                return cached_result
        
        # Initialize Claude analyzer
        analyzer = ClaudeSecurityAnalyzer()
        
        # Perform analysis
        logger.info(f"Analyzing vulnerability: {vulnerability.get('title', 'Unknown')}")
        result = analyzer.analyze_vulnerability(vulnerability)
        
        # Cache the result
        _cache_result(cache_key, result, CACHE_TTL)
        
        # Store in database for analytics
        _store_ai_analysis(vulnerability.get("id"), result)
        
        return result
        
    except Exception as e:
        logger.error(f"AI analysis failed: {str(e)}", exc_info=True)
        raise

@celery_app.task(name="app.tasks.ai_tasks.batch_analyze")
def batch_analyze_task(vulnerabilities: list[Dict[str, Any]], scan_id: str) -> list[Dict[str, Any]]:
    """
    Batch analyze multiple vulnerabilities.
    
    Args:
        vulnerabilities: List of vulnerabilities to analyze
        scan_id: Associated scan ID
        
    Returns:
        List of analysis results
    """
    try:
        analyzer = ClaudeSecurityAnalyzer()
        results = []
        
        # Check for cached results first
        uncached_vulns = []
        for vuln in vulnerabilities:
            cache_key = _generate_cache_key("vuln_analysis", vuln)
            cached_result = _get_cached_result(cache_key)
            
            if cached_result:
                results.append({
                    "vulnerability_id": vuln.get("id"),
                    "analysis": cached_result,
                    "cached": True
                })
            else:
                uncached_vulns.append(vuln)
        
        # Analyze uncached vulnerabilities
        if uncached_vulns:
            logger.info(f"Analyzing {len(uncached_vulns)} uncached vulnerabilities")
            
            # Batch analyze for efficiency
            batch_results = analyzer.batch_analyze(uncached_vulns)
            
            for vuln, analysis in zip(uncached_vulns, batch_results):
                # Cache individual results
                cache_key = _generate_cache_key("vuln_analysis", vuln)
                _cache_result(cache_key, analysis, CACHE_TTL)
                
                # Store in database
                _store_ai_analysis(vuln.get("id"), analysis)
                
                results.append({
                    "vulnerability_id": vuln.get("id"),
                    "analysis": analysis,
                    "cached": False
                })
        
        # Update scan with AI analysis completion
        supabase = get_supabase_client()
        supabase.table("scans").update({
            "ai_analysis_completed": True,
            "ai_analysis_at": datetime.utcnow().isoformat()
        }).eq("id", scan_id).execute()
        
        return results
        
    except Exception as e:
        logger.error(f"Batch AI analysis failed: {str(e)}", exc_info=True)
        raise

@celery_app.task(name="app.tasks.ai_tasks.generate_compliance_report")
def generate_compliance_report_task(scan_id: str, frameworks: list[str]) -> Dict[str, Any]:
    """
    Generate compliance report for scan results.
    
    Args:
        scan_id: Scan to analyze
        frameworks: Compliance frameworks to check
        
    Returns:
        Compliance analysis report
    """
    try:
        # Get scan results
        supabase = get_supabase_client()
        results = supabase.table("scan_results")\
            .select("*")\
            .eq("scan_id", scan_id)\
            .execute()
        
        if not results.data:
            return {"error": "No results found for scan"}
        
        # Generate cache key for compliance report
        cache_key = f"compliance:{scan_id}:{':'.join(sorted(frameworks))}"
        
        # Check cache
        cached_report = _get_cached_result(cache_key)
        if cached_report:
            return cached_report
        
        # Initialize analyzer
        analyzer = ClaudeSecurityAnalyzer()
        
        # Generate compliance analysis
        report = analyzer.analyze_compliance(results.data, frameworks)
        
        # Cache the report
        _cache_result(cache_key, report, CACHE_TTL)
        
        # Store compliance report
        supabase.table("compliance_reports").insert({
            "scan_id": scan_id,
            "frameworks": frameworks,
            "report": report,
            "created_at": datetime.utcnow().isoformat()
        }).execute()
        
        return report
        
    except Exception as e:
        logger.error(f"Compliance report generation failed: {str(e)}", exc_info=True)
        raise

def _generate_cache_key(prefix: str, data: Dict[str, Any]) -> str:
    """Generate a cache key for the given data."""
    # Create a deterministic string representation
    data_str = json.dumps(data, sort_keys=True)
    hash_digest = hashlib.sha256(data_str.encode()).hexdigest()[:16]
    return f"{prefix}:{hash_digest}"

def _get_cached_result(key: str) -> Optional[Dict[str, Any]]:
    """Get cached result from Redis."""
    try:
        redis = get_redis_client()
        cached = redis.get(key)
        if cached:
            return json.loads(cached)
    except Exception as e:
        logger.warning(f"Cache retrieval failed: {e}")
    return None

def _cache_result(key: str, data: Dict[str, Any], ttl: int):
    """Cache result in Redis."""
    try:
        redis = get_redis_client()
        redis.setex(key, ttl, json.dumps(data))
    except Exception as e:
        logger.warning(f"Cache storage failed: {e}")

def _store_ai_analysis(vulnerability_id: str, analysis: Dict[str, Any]):
    """Store AI analysis in database for analytics."""
    try:
        supabase = get_supabase_client()
        supabase.table("ai_analyses").insert({
            "vulnerability_id": vulnerability_id,
            "analysis": analysis,
            "model": "claude-4.0-sonnet",
            "created_at": datetime.utcnow().isoformat()
        }).execute()
    except Exception as e:
        logger.error(f"Failed to store AI analysis: {e}")