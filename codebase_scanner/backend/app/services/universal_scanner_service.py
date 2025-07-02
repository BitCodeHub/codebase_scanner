"""
Enhanced universal scanner service with better error handling and debugging
"""
import os
import json
import asyncio
import subprocess
from typing import Dict, Any, List
from pathlib import Path

class EnhancedUniversalScanner:
    """Enhanced scanner with better debugging"""
    
    async def run_scanner_command(self, cmd: List[str], cwd: str = None) -> Dict[str, Any]:
        """Run scanner command with enhanced error handling"""
        try:
            # Use asyncio subprocess for better control
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=cwd
            )
            
            stdout, stderr = await process.communicate()
            
            return {
                'success': True,
                'stdout': stdout.decode('utf-8', errors='ignore'),
                'stderr': stderr.decode('utf-8', errors='ignore'),
                'returncode': process.returncode
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'stdout': '',
                'stderr': ''
            }
    
    async def scan_python_with_bandit(self, file_path: str) -> List[Dict[str, Any]]:
        """Scan Python file with Bandit"""
        findings = []
        
        cmd = ["bandit", "-r", file_path, "-f", "json", "-ll"]
        result = await self.run_scanner_command(cmd)
        
        if result['stdout']:
            try:
                data = json.loads(result['stdout'])
                for issue in data.get('results', []):
                    findings.append({
                        'tool': 'bandit',
                        'severity': issue.get('issue_severity', 'MEDIUM').lower(),
                        'title': issue.get('issue_text', 'Security issue'),
                        'file': issue.get('filename', ''),
                        'line': issue.get('line_number', 0),
                        'code': issue.get('code', ''),
                        'confidence': issue.get('issue_confidence', 'MEDIUM')
                    })
            except json.JSONDecodeError:
                print(f"Failed to parse Bandit output: {result['stdout'][:200]}")
        
        return findings
    
    async def scan_with_semgrep(self, path: str) -> List[Dict[str, Any]]:
        """Scan with Semgrep"""
        findings = []
        
        # Use a simpler config for better compatibility
        cmd = ["semgrep", "--config=auto", "--json", "--quiet", path]
        result = await self.run_scanner_command(cmd)
        
        if result['stdout']:
            try:
                data = json.loads(result['stdout'])
                for r in data.get('results', []):
                    findings.append({
                        'tool': 'semgrep',
                        'severity': r.get('extra', {}).get('severity', 'medium').lower(),
                        'title': r.get('extra', {}).get('message', r.get('check_id', 'Security issue')),
                        'file': r.get('path', ''),
                        'line': r.get('start', {}).get('line', 0),
                        'code': r.get('extra', {}).get('lines', ''),
                        'rule_id': r.get('check_id', '')
                    })
            except json.JSONDecodeError:
                print(f"Failed to parse Semgrep output: {result['stdout'][:200]}")
        
        return findings
    
    async def scan_for_secrets_simple(self, path: str) -> List[Dict[str, Any]]:
        """Simple secret scanning using grep patterns"""
        findings = []
        
        # Common patterns for secrets
        patterns = [
            (r'["\']?[Aa][Pp][Ii][-_]?[Kk][Ee][Yy]["\']?\s*[:=]\s*["\'][^"\']+["\']', 'API Key'),
            (r'["\']?[Pp][Aa][Ss][Ss][Ww][Oo][Rr][Dd]["\']?\s*[:=]\s*["\'][^"\']+["\']', 'Password'),
            (r'["\']?[Ss][Ee][Cc][Rr][Ee][Tt][-_]?[Kk][Ee][Yy]["\']?\s*[:=]\s*["\'][^"\']+["\']', 'Secret Key'),
            (r'AKIA[0-9A-Z]{16}', 'AWS Access Key'),
            (r'["\']?[Aa][Ww][Ss][-_]?[Ss][Ee][Cc][Rr][Ee][Tt]["\']?\s*[:=]\s*["\'][^"\']+["\']', 'AWS Secret'),
        ]
        
        try:
            # Read file content
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')
            
            # Search for patterns
            import re
            for line_num, line in enumerate(lines, 1):
                for pattern, secret_type in patterns:
                    if re.search(pattern, line, re.IGNORECASE):
                        findings.append({
                            'tool': 'secrets-scanner',
                            'severity': 'high',
                            'title': f'Potential {secret_type} found',
                            'file': path,
                            'line': line_num,
                            'code': line.strip()[:100],
                            'type': 'secret'
                        })
        except Exception as e:
            print(f"Error scanning for secrets: {e}")
        
        return findings
    
    async def scan_file_comprehensive(self, file_path: str) -> Dict[str, Any]:
        """Comprehensive scan of a single file"""
        results = {
            'file': file_path,
            'findings': [],
            'language': None
        }
        
        # Detect language
        ext = Path(file_path).suffix.lower()
        language_map = {
            '.py': 'python',
            '.js': 'javascript',
            '.jsx': 'javascript',
            '.ts': 'typescript',
            '.tsx': 'typescript',
            '.java': 'java',
            '.go': 'go',
            '.rb': 'ruby',
            '.php': 'php',
            '.cs': 'csharp',
            '.cpp': 'cpp',
            '.c': 'c',
            '.rs': 'rust',
            '.swift': 'swift',
            '.kt': 'kotlin',
            '.scala': 'scala',
            '.r': 'r',
            '.lua': 'lua',
            '.pl': 'perl',
            '.sh': 'bash',
            '.yaml': 'yaml',
            '.yml': 'yaml',
            '.json': 'json',
            '.xml': 'xml',
            '.sql': 'sql'
        }
        
        results['language'] = language_map.get(ext, 'unknown')
        
        # Always scan for secrets
        print(f"🔐 Scanning for secrets in {file_path}")
        secret_findings = await self.scan_for_secrets_simple(file_path)
        results['findings'].extend(secret_findings)
        
        # Language-specific scanning
        if ext == '.py':
            print(f"🐍 Running Bandit on {file_path}")
            bandit_findings = await self.scan_python_with_bandit(file_path)
            results['findings'].extend(bandit_findings)
        
        # Semgrep for all languages
        print(f"🔧 Running Semgrep on {file_path}")
        semgrep_findings = await self.scan_with_semgrep(file_path)
        results['findings'].extend(semgrep_findings)
        
        # Summary
        results['total_findings'] = len(results['findings'])
        results['secrets_found'] = len([f for f in results['findings'] if f.get('type') == 'secret'])
        
        return results