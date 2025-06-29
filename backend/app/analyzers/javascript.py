import os
import json
from typing import List, Dict, Any
from app.analyzers.base import BaseAnalyzer
import logging

logger = logging.getLogger(__name__)

class JavaScriptAnalyzer(BaseAnalyzer):
    """JavaScript/TypeScript code analyzer using ESLint and Semgrep"""
    
    def __init__(self):
        super().__init__()
        self.supported_extensions = ['.js', '.jsx', '.ts', '.tsx']
    
    async def analyze(self, code_path: str) -> List[Dict[str, Any]]:
        """Analyze JavaScript/TypeScript code for security issues"""
        results = []
        
        # Run ESLint with security plugin
        eslint_results = await self._run_eslint(code_path)
        results.extend(eslint_results)
        
        # Run Semgrep
        semgrep_results = await self._run_semgrep(code_path)
        results.extend(semgrep_results)
        
        return results
    
    async def _run_eslint(self, code_path: str) -> List[Dict[str, Any]]:
        """Run ESLint with security plugins"""
        results = []
        
        try:
            # Create ESLint config if not exists
            eslint_config = {
                "env": {
                    "browser": True,
                    "es2021": True,
                    "node": True
                },
                "extends": [
                    "eslint:recommended",
                    "plugin:security/recommended"
                ],
                "plugins": ["security"],
                "parserOptions": {
                    "ecmaVersion": "latest",
                    "sourceType": "module"
                }
            }
            
            config_path = os.path.join(code_path, '.eslintrc.json')
            with open(config_path, 'w') as f:
                json.dump(eslint_config, f)
            
            # Run eslint command
            command = [
                'eslint',
                code_path,
                '--format', 'json',
                '--ext', '.js,.jsx,.ts,.tsx'
            ]
            
            result = self._run_command(command)
            
            if result.stdout:
                output = json.loads(result.stdout)
                
                for file_result in output:
                    for message in file_result.get('messages', []):
                        finding = {
                            'rule_id': f"eslint-{message.get('ruleId', 'unknown')}",
                            'title': message.get('message', 'Code issue'),
                            'severity': self._map_eslint_severity(message.get('severity', 1)),
                            'category': 'security' if 'security' in message.get('ruleId', '') else 'quality',
                            'file_path': file_result.get('filePath'),
                            'line_number': message.get('line'),
                            'column_number': message.get('column'),
                            'analyzer': 'eslint',
                            'raw_output': message
                        }
                        
                        results.append(finding)
            
            # Cleanup config
            os.remove(config_path)
        
        except Exception as e:
            logger.error(f"Error running ESLint: {e}")
        
        return results
    
    async def _run_semgrep(self, code_path: str) -> List[Dict[str, Any]]:
        """Run Semgrep scanner for JavaScript"""
        results = []
        
        try:
            # Run semgrep with JavaScript/TypeScript rules
            command = [
                'semgrep',
                '--config=p/javascript',
                '--config=p/typescript',
                '--config=p/security-audit',
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
    
    def _map_eslint_severity(self, severity: int) -> str:
        """Map ESLint severity to our standard"""
        if severity == 2:
            return 'high'
        elif severity == 1:
            return 'medium'
        else:
            return 'low'
    
    def _map_semgrep_severity(self, severity: str) -> str:
        """Map Semgrep severity to our standard"""
        mapping = {
            'ERROR': 'critical',
            'WARNING': 'high',
            'INFO': 'medium',
            'NOTE': 'low'
        }
        return mapping.get(severity.upper(), 'medium')