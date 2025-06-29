import os
import json
from typing import Dict, Any
from datetime import datetime
from sqlalchemy import select
from app.models.scan import Scan, ScanResult
from app.utils.database import AsyncSessionLocal
import logging

logger = logging.getLogger(__name__)

class ReportGenerator:
    """Generate various types of reports from scan results"""
    
    def __init__(self):
        self.owasp_mapping = {
            'sql_injection': 'A03:2021',
            'xss': 'A03:2021',
            'broken_auth': 'A07:2021',
            'sensitive_data': 'A02:2021',
            'xxe': 'A05:2021',
            'broken_access': 'A01:2021',
            'security_misconfig': 'A05:2021',
            'vulnerable_component': 'A06:2021',
            'insufficient_logging': 'A09:2021',
            'ssrf': 'A10:2021'
        }
    
    async def generate(self, scan: Scan, report_type: str) -> Dict[str, Any]:
        """Generate report based on scan results"""
        async with AsyncSessionLocal() as db:
            # Get scan results
            results = await db.execute(
                select(ScanResult).where(ScanResult.scan_id == scan.id)
            )
            scan_results = results.scalars().all()
            
            if report_type == 'security':
                return await self._generate_security_report(scan, scan_results)
            elif report_type == 'compliance':
                return await self._generate_compliance_report(scan, scan_results)
            elif report_type == 'executive':
                return await self._generate_executive_report(scan, scan_results)
            else:
                raise ValueError(f"Unknown report type: {report_type}")
    
    async def _generate_security_report(self, scan: Scan, results: list) -> Dict[str, Any]:
        """Generate detailed security report"""
        # Group results by severity
        findings_by_severity = {
            'critical': [],
            'high': [],
            'medium': [],
            'low': [],
            'info': []
        }
        
        for result in results:
            if not result.false_positive:
                finding = {
                    'id': result.id,
                    'title': result.title,
                    'description': result.description,
                    'file_path': result.file_path,
                    'line_number': result.line_number,
                    'category': result.category,
                    'vulnerability_type': result.vulnerability_type,
                    'fix_recommendation': result.fix_recommendation,
                    'ai_generated_fix': result.ai_generated_fix,
                    'references': result.references
                }
                findings_by_severity[result.severity.value].append(finding)
        
        # Calculate security score
        total_issues = len(results)
        critical_weight = len(findings_by_severity['critical']) * 10
        high_weight = len(findings_by_severity['high']) * 5
        medium_weight = len(findings_by_severity['medium']) * 2
        low_weight = len(findings_by_severity['low']) * 1
        
        total_weight = critical_weight + high_weight + medium_weight + low_weight
        security_score = max(0, 100 - total_weight)
        
        # Determine launch readiness
        launch_ready = (
            len(findings_by_severity['critical']) == 0 and
            len(findings_by_severity['high']) <= 3 and
            security_score >= 70
        )
        
        return {
            'summary': f"Security scan completed with {total_issues} issues found",
            'findings': findings_by_severity,
            'statistics': {
                'total_issues': total_issues,
                'critical': len(findings_by_severity['critical']),
                'high': len(findings_by_severity['high']),
                'medium': len(findings_by_severity['medium']),
                'low': len(findings_by_severity['low']),
                'info': len(findings_by_severity['info'])
            },
            'security_score': security_score,
            'launch_ready': launch_ready,
            'scan_info': {
                'scan_id': scan.id,
                'scan_type': scan.scan_type.value,
                'started_at': scan.started_at.isoformat() if scan.started_at else None,
                'completed_at': scan.completed_at.isoformat() if scan.completed_at else None,
                'duration_minutes': (
                    (scan.completed_at - scan.started_at).total_seconds() / 60
                    if scan.started_at and scan.completed_at else None
                )
            }
        }
    
    async def _generate_compliance_report(self, scan: Scan, results: list) -> Dict[str, Any]:
        """Generate compliance report (OWASP, CWE)"""
        owasp_issues = {}
        cwe_issues = {}
        
        for result in results:
            if result.false_positive:
                continue
            
            # Map to OWASP
            owasp_category = self.owasp_mapping.get(
                result.vulnerability_type,
                'A00:Unknown'
            )
            if owasp_category not in owasp_issues:
                owasp_issues[owasp_category] = []
            owasp_issues[owasp_category].append({
                'title': result.title,
                'severity': result.severity.value,
                'file': result.file_path
            })
            
            # Map to CWE
            for ref in result.references or []:
                if ref.startswith('CWE-'):
                    if ref not in cwe_issues:
                        cwe_issues[ref] = []
                    cwe_issues[ref].append({
                        'title': result.title,
                        'severity': result.severity.value,
                        'file': result.file_path
                    })
        
        # Calculate compliance percentage
        owasp_coverage = len(owasp_issues) / 10 * 100  # OWASP Top 10
        critical_high_issues = sum(
            1 for r in results 
            if r.severity.value in ['critical', 'high'] and not r.false_positive
        )
        
        overall_compliance = max(0, 100 - (critical_high_issues * 10))
        
        return {
            'summary': f"Compliance report for scan {scan.id}",
            'compliance': {
                'owasp_top_10': owasp_issues,
                'cwe_sans_top_25': cwe_issues,
                'overall_compliance': overall_compliance,
                'owasp_coverage': owasp_coverage
            },
            'findings': await self._generate_security_report(scan, results),
            'recommendations': self._generate_compliance_recommendations(owasp_issues)
        }
    
    async def _generate_executive_report(self, scan: Scan, results: list) -> Dict[str, Any]:
        """Generate high-level executive report"""
        security_report = await self._generate_security_report(scan, results)
        
        # Risk assessment
        risk_level = 'Low'
        if security_report['statistics']['critical'] > 0:
            risk_level = 'Critical'
        elif security_report['statistics']['high'] > 5:
            risk_level = 'High'
        elif security_report['statistics']['medium'] > 10:
            risk_level = 'Medium'
        
        return {
            'summary': f"Executive Summary - {scan.project.name}",
            'risk_assessment': {
                'overall_risk': risk_level,
                'security_score': security_report['security_score'],
                'launch_ready': security_report['launch_ready'],
                'critical_issues': security_report['statistics']['critical'],
                'high_issues': security_report['statistics']['high']
            },
            'key_findings': self._get_key_findings(results),
            'recommendations': self._get_executive_recommendations(security_report),
            'statistics': security_report['statistics'],
            'scan_date': scan.created_at.isoformat()
        }
    
    def _generate_compliance_recommendations(self, owasp_issues: Dict) -> list:
        """Generate compliance-specific recommendations"""
        recommendations = []
        
        if 'A01:2021' in owasp_issues:
            recommendations.append({
                'category': 'Access Control',
                'recommendation': 'Implement proper access control mechanisms and validate user permissions'
            })
        
        if 'A02:2021' in owasp_issues:
            recommendations.append({
                'category': 'Cryptography',
                'recommendation': 'Use strong encryption for sensitive data and implement proper key management'
            })
        
        if 'A03:2021' in owasp_issues:
            recommendations.append({
                'category': 'Injection',
                'recommendation': 'Validate and sanitize all user inputs, use parameterized queries'
            })
        
        return recommendations
    
    def _get_key_findings(self, results: list) -> list:
        """Extract key findings for executive report"""
        key_findings = []
        
        # Get top 5 critical/high issues
        critical_high = [
            r for r in results 
            if r.severity.value in ['critical', 'high'] and not r.false_positive
        ][:5]
        
        for result in critical_high:
            key_findings.append({
                'title': result.title,
                'severity': result.severity.value,
                'impact': self._assess_impact(result),
                'recommendation': result.fix_recommendation or 'Review and fix the identified issue'
            })
        
        return key_findings
    
    def _get_executive_recommendations(self, security_report: Dict) -> list:
        """Generate executive-level recommendations"""
        recommendations = []
        
        if security_report['statistics']['critical'] > 0:
            recommendations.append({
                'priority': 'Immediate',
                'action': 'Address all critical security vulnerabilities before deployment'
            })
        
        if security_report['security_score'] < 70:
            recommendations.append({
                'priority': 'High',
                'action': 'Improve overall security posture to achieve minimum security score of 70'
            })
        
        if not security_report['launch_ready']:
            recommendations.append({
                'priority': 'High',
                'action': 'Resolve blocking issues to achieve LaunchReady status'
            })
        
        return recommendations
    
    def _assess_impact(self, result: ScanResult) -> str:
        """Assess the business impact of a vulnerability"""
        if result.vulnerability_type in ['sql_injection', 'broken_auth']:
            return 'Data breach risk, potential complete system compromise'
        elif result.vulnerability_type == 'xss':
            return 'User data theft, session hijacking'
        elif result.vulnerability_type == 'sensitive_data':
            return 'Compliance violations, data exposure'
        else:
            return 'Security risk requiring immediate attention'
    
    async def save_to_file(self, report_content: Dict, format: str, output_dir: str) -> str:
        """Save report to file"""
        os.makedirs(output_dir, exist_ok=True)
        timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
        
        if format == 'json':
            file_path = os.path.join(output_dir, f'report_{timestamp}.json')
            with open(file_path, 'w') as f:
                json.dump(report_content, f, indent=2)
        
        elif format == 'sarif':
            # Convert to SARIF format
            sarif_report = self._convert_to_sarif(report_content)
            file_path = os.path.join(output_dir, f'report_{timestamp}.sarif')
            with open(file_path, 'w') as f:
                json.dump(sarif_report, f, indent=2)
        
        elif format == 'pdf':
            # PDF generation would require additional libraries
            raise NotImplementedError("PDF generation not yet implemented")
        
        return file_path
    
    def _convert_to_sarif(self, report_content: Dict) -> Dict:
        """Convert report to SARIF format for GitHub integration"""
        sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "Codebase Scanner",
                        "version": "1.0.0",
                        "informationUri": "https://codebase-scanner.example.com"
                    }
                },
                "results": []
            }]
        }
        
        # Convert findings to SARIF results
        for severity, findings in report_content.get('findings', {}).items():
            for finding in findings:
                result = {
                    "ruleId": finding.get('vulnerability_type', 'unknown'),
                    "level": self._map_to_sarif_level(severity),
                    "message": {
                        "text": finding.get('title', 'Security issue')
                    },
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": finding.get('file_path', '')
                            },
                            "region": {
                                "startLine": finding.get('line_number', 1)
                            }
                        }
                    }]
                }
                sarif["runs"][0]["results"].append(result)
        
        return sarif
    
    def _map_to_sarif_level(self, severity: str) -> str:
        """Map our severity to SARIF level"""
        mapping = {
            'critical': 'error',
            'high': 'error',
            'medium': 'warning',
            'low': 'note',
            'info': 'note'
        }
        return mapping.get(severity, 'warning')