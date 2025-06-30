"""
Claude AI service for security vulnerability analysis.
"""

import json
import os
from typing import Dict, Any, List, Optional
import anthropic
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


class ClaudeSecurityAnalyzer:
    """Service for analyzing security vulnerabilities using Claude AI."""
    
    def __init__(self):
        """Initialize Claude client with API key."""
        api_key = os.getenv("ANTHROPIC_API_KEY")
        if not api_key:
            raise ValueError("ANTHROPIC_API_KEY environment variable is required")
        
        self.client = anthropic.Anthropic(api_key=api_key)
        self.model = "claude-3-sonnet-20240229"
    
    def analyze_vulnerability(self, vulnerability: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze a single vulnerability using Claude.
        
        Args:
            vulnerability: Vulnerability data from scan
            
        Returns:
            Detailed analysis results
        """
        try:
            prompt = self._build_vulnerability_prompt(vulnerability)
            
            message = self.client.messages.create(
                model=self.model,
                max_tokens=2500,
                temperature=0,
                system=self._get_system_prompt(),
                messages=[
                    {
                        "role": "user",
                        "content": prompt
                    }
                ]
            )
            
            # Parse response
            response_text = message.content[0].text
            analysis = self._parse_analysis_response(response_text)
            
            # Add metadata
            analysis['analyzed_at'] = datetime.utcnow().isoformat()
            analysis['model'] = self.model
            analysis['vulnerability_id'] = vulnerability.get('id')
            
            return analysis
            
        except Exception as e:
            logger.error(f"Claude analysis failed: {e}")
            raise
    
    def batch_analyze(self, vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Analyze multiple vulnerabilities efficiently.
        
        Args:
            vulnerabilities: List of vulnerabilities to analyze
            
        Returns:
            List of analysis results
        """
        results = []
        
        # For now, analyze individually - could be optimized with batch prompts
        for vuln in vulnerabilities:
            try:
                analysis = self.analyze_vulnerability(vuln)
                results.append(analysis)
            except Exception as e:
                logger.error(f"Failed to analyze vulnerability {vuln.get('id')}: {e}")
                # Add error result
                results.append({
                    'vulnerability_id': vuln.get('id'),
                    'error': str(e),
                    'analyzed_at': datetime.utcnow().isoformat()
                })
        
        return results
    
    def analyze_compliance(self, scan_results: List[Dict[str, Any]], frameworks: List[str]) -> Dict[str, Any]:
        """
        Analyze scan results for compliance violations.
        
        Args:
            scan_results: List of vulnerability findings
            frameworks: Compliance frameworks to check (OWASP, PCI-DSS, etc.)
            
        Returns:
            Compliance analysis report
        """
        try:
            prompt = self._build_compliance_prompt(scan_results, frameworks)
            
            message = self.client.messages.create(
                model=self.model,
                max_tokens=3000,
                temperature=0,
                system="You are a compliance expert analyzing security scan results for regulatory violations.",
                messages=[
                    {
                        "role": "user",
                        "content": prompt
                    }
                ]
            )
            
            response_text = message.content[0].text
            compliance_report = self._parse_compliance_response(response_text)
            
            compliance_report['analyzed_at'] = datetime.utcnow().isoformat()
            compliance_report['frameworks'] = frameworks
            
            return compliance_report
            
        except Exception as e:
            logger.error(f"Compliance analysis failed: {e}")
            raise
    
    def _build_vulnerability_prompt(self, vulnerability: Dict[str, Any]) -> str:
        """Build analysis prompt for a vulnerability."""
        return f"""Analyze this security vulnerability and provide detailed recommendations:

**Vulnerability Details:**
- CWE ID: {vulnerability.get('rule_id', 'Unknown')}
- Type: {vulnerability.get('vulnerability_type', vulnerability.get('category', 'Unknown'))}
- OWASP Category: {vulnerability.get('owasp_category', 'Unknown')}
- Severity: {vulnerability.get('severity', 'Unknown')}
- File: {vulnerability.get('file_path', 'Unknown')}
- Line: {vulnerability.get('line_number', 'Unknown')}
- Language: {vulnerability.get('language', 'Unknown')}

**Code Context:**
```{vulnerability.get('language', 'text')}
{vulnerability.get('code_snippet', 'No code snippet available')}
```

**Description:** {vulnerability.get('description', 'No description available')}

Please provide a comprehensive analysis in JSON format with these exact keys:
- risk_description: Detailed explanation of the security risk
- plain_english_explanation: Non-technical explanation for stakeholders
- fix_suggestions: Array of specific remediation suggestions
- code_fix: Example of corrected code (if applicable)
- compliance_violations: Object mapping frameworks to violations
- remediation_steps: Array of step-by-step remediation instructions
- severity_justification: Explanation of why this severity was assigned
- references: Array of helpful links and documentation

Ensure the response is valid JSON."""
    
    def _build_compliance_prompt(self, scan_results: List[Dict[str, Any]], frameworks: List[str]) -> str:
        """Build compliance analysis prompt."""
        # Summarize vulnerabilities by category and severity
        summary = self._summarize_vulnerabilities(scan_results)
        
        return f"""Analyze these security scan results for compliance violations:

**Scan Summary:**
- Total vulnerabilities: {len(scan_results)}
- By severity: {summary['by_severity']}
- By category: {summary['by_category']}

**Frameworks to check:** {', '.join(frameworks)}

**Sample vulnerabilities:**
{self._format_sample_vulnerabilities(scan_results[:10])}

Please provide a compliance analysis in JSON format with:
- overall_compliance_score: Percentage score (0-100)
- framework_analysis: Object with analysis for each framework
- critical_violations: Array of most serious compliance issues
- recommendations: Array of prioritized remediation actions
- risk_assessment: Overall risk level and justification
- regulatory_impact: Potential regulatory consequences

Focus on actionable insights and prioritized recommendations."""
    
    def _get_system_prompt(self) -> str:
        """Get the system prompt for Claude."""
        return """You are a senior security engineer and vulnerability analyst with expertise in:
- OWASP Top 10 and security best practices
- Common Weakness Enumeration (CWE) categories
- Secure coding practices across multiple languages
- Compliance frameworks (PCI-DSS, GDPR, SOC2, HIPAA)
- Risk assessment and threat modeling

Provide detailed, actionable security analysis that helps developers understand and fix vulnerabilities. Always format responses as valid JSON when requested."""
    
    def _parse_analysis_response(self, response_text: str) -> Dict[str, Any]:
        """Parse Claude's vulnerability analysis response."""
        try:
            # Extract JSON from response
            json_start = response_text.find('{')
            json_end = response_text.rfind('}') + 1
            
            if json_start != -1 and json_end > json_start:
                json_text = response_text[json_start:json_end]
                return json.loads(json_text)
            else:
                raise ValueError("No JSON found in response")
                
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse JSON response: {e}")
            # Return structured fallback
            return {
                'error': 'Failed to parse AI response',
                'raw_response': response_text,
                'risk_description': 'Analysis failed - manual review required',
                'plain_english_explanation': 'The AI analysis could not be completed.',
                'fix_suggestions': ['Manual security review recommended'],
                'code_fix': None,
                'compliance_violations': {},
                'remediation_steps': ['Review vulnerability manually'],
                'severity_justification': 'Unable to assess automatically',
                'references': []
            }
    
    def _parse_compliance_response(self, response_text: str) -> Dict[str, Any]:
        """Parse Claude's compliance analysis response."""
        try:
            json_start = response_text.find('{')
            json_end = response_text.rfind('}') + 1
            
            if json_start != -1 and json_end > json_start:
                json_text = response_text[json_start:json_end]
                return json.loads(json_text)
            else:
                raise ValueError("No JSON found in compliance response")
                
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse compliance JSON: {e}")
            return {
                'error': 'Failed to parse compliance analysis',
                'overall_compliance_score': 0,
                'framework_analysis': {},
                'critical_violations': [],
                'recommendations': ['Manual compliance review required'],
                'risk_assessment': 'Unable to assess automatically',
                'regulatory_impact': 'Unknown - manual review needed'
            }
    
    def _summarize_vulnerabilities(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Summarize vulnerabilities for compliance analysis."""
        summary = {
            'by_severity': {},
            'by_category': {}
        }
        
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'unknown').lower()
            category = vuln.get('category', 'unknown')
            
            summary['by_severity'][severity] = summary['by_severity'].get(severity, 0) + 1
            summary['by_category'][category] = summary['by_category'].get(category, 0) + 1
        
        return summary
    
    def _format_sample_vulnerabilities(self, vulnerabilities: List[Dict[str, Any]]) -> str:
        """Format sample vulnerabilities for prompt."""
        formatted = []
        for i, vuln in enumerate(vulnerabilities, 1):
            formatted.append(f"{i}. {vuln.get('title', 'Unknown')} ({vuln.get('severity', 'Unknown')} severity)")
        
        return '\n'.join(formatted)