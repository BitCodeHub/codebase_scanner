import os
import json
from typing import List, Dict, Any
from app.analyzers.base import BaseAnalyzer
import logging

logger = logging.getLogger(__name__)

class PythonAnalyzer(BaseAnalyzer):
    """Python code analyzer using Bandit and Semgrep"""
    
    def __init__(self):
        super().__init__()
        self.supported_extensions = ['.py', '.pyw']
    
    async def analyze(self, code_path: str) -> List[Dict[str, Any]]:
        """Analyze Python code for security issues"""
        results = []
        
        # Run Bandit
        bandit_results = await self._run_bandit(code_path)
        results.extend(bandit_results)
        
        # Run Semgrep
        semgrep_results = await self._run_semgrep(code_path)
        results.extend(semgrep_results)
        
        return results
    
    async def _run_bandit(self, code_path: str) -> List[Dict[str, Any]]:
        """Run Bandit security scanner"""
        results = []
        
        try:
            # Run bandit command
            command = [
                'bandit',
                '-r',
                code_path,
                '-f', 'json',
                '-ll'  # Only report medium severity and above
            ]
            
            result = self._run_command(command)
            
            if result.returncode in [0, 1]:  # Bandit returns 1 if issues found
                output = json.loads(result.stdout)
                
                for issue in output.get('results', []):
                    finding = {
                        'rule_id': f"bandit-{issue.get('test_id', 'unknown')}",
                        'title': issue.get('issue_text', 'Security issue'),
                        'description': issue.get('issue_text'),
                        'severity': self._map_bandit_severity(issue.get('issue_severity', 'MEDIUM')),
                        'category': 'security',
                        'file_path': issue.get('filename'),
                        'line_number': issue.get('line_number'),
                        'column_number': issue.get('col_offset'),
                        'code_snippet': issue.get('code'),
                        'vulnerability_type': issue.get('test_name'),
                        'confidence': issue.get('issue_confidence', 'MEDIUM').lower(),
                        'analyzer': 'bandit',
                        'raw_output': issue
                    }
                    
                    # Add CWE reference if available
                    if issue.get('issue_cwe'):
                        finding['references'] = [f"CWE-{issue['issue_cwe']['id']}"]
                    
                    results.append(finding)
        
        except Exception as e:
            logger.error(f"Error running Bandit: {e}")
        
        return results
    
    async def _run_semgrep(self, code_path: str) -> List[Dict[str, Any]]:
        """Run Semgrep scanner"""
        results = []
        
        try:
            # Run semgrep command
            command = [
                'semgrep',
                '--config=auto',
                '--json',
                '--no-git-ignore',
                code_path
            ]
            
            result = self._run_command(command)
            
            if result.returncode == 0:
                output = json.loads(result.stdout)
                
                for finding in output.get('results', []):
                    result_dict = {
                        'rule_id': finding.get('check_id'),
                        'title': finding.get('extra', {}).get('message', 'Security issue'),
                        'description': finding.get('extra', {}).get('metadata', {}).get('description'),
                        'severity': self._map_semgrep_severity(finding.get('extra', {}).get('severity', 'WARNING')),
                        'category': finding.get('extra', {}).get('metadata', {}).get('category', 'security'),
                        'file_path': finding.get('path'),
                        'line_number': finding.get('start', {}).get('line'),
                        'column_number': finding.get('start', {}).get('col'),
                        'code_snippet': finding.get('extra', {}).get('lines'),
                        'vulnerability_type': finding.get('extra', {}).get('metadata', {}).get('cwe', ''),
                        'confidence': 'high',
                        'fix_recommendation': finding.get('extra', {}).get('fix'),
                        'references': finding.get('extra', {}).get('metadata', {}).get('references', []),
                        'analyzer': 'semgrep',
                        'raw_output': finding
                    }
                    
                    results.append(result_dict)
        
        except Exception as e:
            logger.error(f"Error running Semgrep: {e}")
        
        return results
    
    def _map_bandit_severity(self, severity: str) -> str:
        """Map Bandit severity to our standard"""
        mapping = {
            'HIGH': 'high',
            'MEDIUM': 'medium',
            'LOW': 'low'
        }
        return mapping.get(severity.upper(), 'medium')
    
    def _map_semgrep_severity(self, severity: str) -> str:
        """Map Semgrep severity to our standard"""
        mapping = {
            'ERROR': 'critical',
            'WARNING': 'high',
            'INFO': 'medium',
            'NOTE': 'low'
        }
        return mapping.get(severity.upper(), 'medium')