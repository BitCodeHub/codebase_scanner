"""
Comprehensive Security Scanner Service
Supports: Web apps, APIs, mobile apps, desktop apps, infrastructure code, and more
"""
import os
import json
import asyncio
import subprocess
import tempfile
import re
from typing import Dict, List, Any, Optional
from pathlib import Path
import yaml
import logging

logger = logging.getLogger(__name__)

class ComprehensiveSecurityScanner:
    """
    Comprehensive security scanner supporting multiple languages and frameworks
    """
    
    def __init__(self):
        self.scan_results = {
            'vulnerabilities': [],
            'secrets': [],
            'dependencies': [],
            'code_quality': [],
            'compliance': [],
            'infrastructure': []
        }
        
        # Language detection patterns
        self.language_patterns = {
            'python': ['.py', '.pyw', '.pyx', '.pyd', 'requirements.txt', 'Pipfile', 'pyproject.toml'],
            'javascript': ['.js', '.jsx', '.mjs', '.ts', '.tsx', 'package.json', '.npmrc'],
            'java': ['.java', '.class', '.jar', 'pom.xml', 'build.gradle'],
            'csharp': ['.cs', '.csx', '.vb', '.csproj', '.sln'],
            'go': ['.go', 'go.mod', 'go.sum'],
            'ruby': ['.rb', '.erb', 'Gemfile', 'Rakefile'],
            'php': ['.php', '.phtml', '.php3', '.php4', '.php5', 'composer.json'],
            'rust': ['.rs', 'Cargo.toml', 'Cargo.lock'],
            'swift': ['.swift', 'Package.swift'],
            'kotlin': ['.kt', '.kts', 'build.gradle.kts'],
            'cpp': ['.cpp', '.cc', '.cxx', '.hpp', '.h', '.c'],
            'web': ['.html', '.htm', '.css', '.scss', '.sass', '.less'],
            'infrastructure': ['.tf', '.yml', '.yaml', 'Dockerfile', '.dockerignore', 'docker-compose.yml'],
            'mobile': ['AndroidManifest.xml', 'Info.plist', '.apk', '.ipa', '.aab'],
            'sql': ['.sql', '.mysql', '.pgsql', '.sqlite'],
            'config': ['.env', '.ini', '.conf', '.cfg', '.json', '.xml', '.properties']
        }
    
    async def run_command_async(self, cmd: List[str], timeout: int = 300) -> Dict[str, Any]:
        """Run command asynchronously with timeout"""
        try:
            logger.info(f"Running: {' '.join(cmd[:3])}...")
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=timeout
            )
            
            return {
                'success': process.returncode in [0, 1],  # Some tools return 1 when findings exist
                'stdout': stdout.decode('utf-8', errors='ignore'),
                'stderr': stderr.decode('utf-8', errors='ignore'),
                'returncode': process.returncode
            }
        except asyncio.TimeoutError:
            logger.error(f"Command timed out: {cmd[0]}")
            return {'success': False, 'error': 'timeout', 'stdout': '', 'stderr': ''}
        except Exception as e:
            logger.error(f"Command error: {e}")
            return {'success': False, 'error': str(e), 'stdout': '', 'stderr': ''}
    
    async def detect_project_type(self, directory: str) -> Dict[str, Any]:
        """Detect project type and technologies used"""
        detected = {
            'languages': set(),
            'frameworks': set(),
            'project_types': set(),
            'package_managers': set(),
            'has_web_frontend': False,
            'has_api': False,
            'has_mobile': False,
            'has_infrastructure': False,
            'has_database': False
        }
        
        for root, dirs, files in os.walk(directory):
            for file in files:
                file_lower = file.lower()
                ext = Path(file).suffix.lower()
                
                # Detect languages
                for lang, patterns in self.language_patterns.items():
                    if any(file.endswith(p) or file == p for p in patterns):
                        detected['languages'].add(lang)
                
                # Detect frameworks
                if file == 'package.json':
                    detected['package_managers'].add('npm')
                    try:
                        with open(os.path.join(root, file), 'r') as f:
                            pkg = json.load(f)
                            deps = {**pkg.get('dependencies', {}), **pkg.get('devDependencies', {})}
                            if 'react' in deps:
                                detected['frameworks'].add('react')
                            if 'vue' in deps:
                                detected['frameworks'].add('vue')
                            if 'angular' in deps:
                                detected['frameworks'].add('angular')
                            if 'express' in deps:
                                detected['frameworks'].add('express')
                                detected['has_api'] = True
                            if 'next' in deps:
                                detected['frameworks'].add('nextjs')
                    except:
                        pass
                
                elif file == 'requirements.txt' or file == 'Pipfile':
                    detected['package_managers'].add('pip')
                    try:
                        with open(os.path.join(root, file), 'r') as f:
                            content = f.read().lower()
                            if 'django' in content:
                                detected['frameworks'].add('django')
                                detected['has_web_frontend'] = True
                            if 'flask' in content:
                                detected['frameworks'].add('flask')
                                detected['has_api'] = True
                            if 'fastapi' in content:
                                detected['frameworks'].add('fastapi')
                                detected['has_api'] = True
                    except:
                        pass
                
                elif file == 'pom.xml':
                    detected['package_managers'].add('maven')
                    detected['frameworks'].add('spring')
                    detected['has_api'] = True
                
                elif file == 'Gemfile':
                    detected['package_managers'].add('bundler')
                    detected['frameworks'].add('rails')
                    detected['has_web_frontend'] = True
                
                # Detect project types
                if file in ['AndroidManifest.xml', 'build.gradle'] and 'android' in root.lower():
                    detected['project_types'].add('android')
                    detected['has_mobile'] = True
                
                elif file == 'Info.plist' and any(x in root for x in ['ios', 'iOS']):
                    detected['project_types'].add('ios')
                    detected['has_mobile'] = True
                
                elif file in ['Dockerfile', 'docker-compose.yml', '.dockerignore']:
                    detected['project_types'].add('containerized')
                    detected['has_infrastructure'] = True
                
                elif ext in ['.tf', '.tfvars']:
                    detected['project_types'].add('terraform')
                    detected['has_infrastructure'] = True
                
                elif ext in ['.sql', '.mysql', '.pgsql']:
                    detected['has_database'] = True
                
                elif file_lower in ['index.html', 'index.htm'] or ext in ['.html', '.css', '.js']:
                    detected['has_web_frontend'] = True
        
        # Determine overall project types
        if detected['has_web_frontend']:
            detected['project_types'].add('web_application')
        if detected['has_api']:
            detected['project_types'].add('api_service')
        if detected['has_mobile']:
            detected['project_types'].add('mobile_application')
        if detected['has_infrastructure']:
            detected['project_types'].add('infrastructure')
        
        # Convert sets to lists for JSON serialization
        return {
            'languages': list(detected['languages']),
            'frameworks': list(detected['frameworks']),
            'project_types': list(detected['project_types']),
            'package_managers': list(detected['package_managers']),
            'has_web_frontend': detected['has_web_frontend'],
            'has_api': detected['has_api'],
            'has_mobile': detected['has_mobile'],
            'has_infrastructure': detected['has_infrastructure'],
            'has_database': detected['has_database']
        }
    
    async def scan_with_semgrep(self, directory: str) -> List[Dict[str, Any]]:
        """Run Semgrep with multiple rulesets"""
        findings = []
        
        # Different rule sets for comprehensive scanning
        rulesets = [
            "auto",  # Auto-detect and apply relevant rules
            "p/security-audit",  # Security audit rules
            "p/owasp-top-ten",  # OWASP Top 10
            "p/cwe-top-25",  # CWE Top 25
            "p/dockerfile",  # Docker security
            "p/kubernetes",  # K8s security
            "p/terraform",  # IaC security
            "p/jwt",  # JWT security
            "p/xss",  # Cross-site scripting
            "p/sql-injection",  # SQL injection
            "p/command-injection",  # Command injection
            "p/secrets",  # Hardcoded secrets
        ]
        
        for ruleset in rulesets:
            cmd = ["semgrep", f"--config={ruleset}", "--json", directory]
            result = await self.run_command_async(cmd, timeout=180)
            
            if result['stdout']:
                try:
                    data = json.loads(result['stdout'])
                    for r in data.get('results', []):
                        finding = {
                            'tool': 'semgrep',
                            'ruleset': ruleset,
                            'severity': r.get('extra', {}).get('severity', 'medium'),
                            'title': r.get('extra', {}).get('message', r.get('check_id', 'Unknown')),
                            'file': r.get('path', ''),
                            'line': r.get('start', {}).get('line', 0),
                            'end_line': r.get('end', {}).get('line', 0),
                            'code': r.get('extra', {}).get('lines', ''),
                            'rule_id': r.get('check_id', ''),
                            'cwe': r.get('extra', {}).get('metadata', {}).get('cwe', []),
                            'owasp': r.get('extra', {}).get('metadata', {}).get('owasp', []),
                            'fix': r.get('extra', {}).get('fix', ''),
                            'references': r.get('extra', {}).get('metadata', {}).get('references', [])
                        }
                        findings.append(finding)
                except json.JSONDecodeError:
                    logger.error(f"Failed to parse Semgrep output for {ruleset}")
        
        return findings
    
    async def scan_secrets_comprehensive(self, directory: str) -> List[Dict[str, Any]]:
        """Comprehensive secret scanning with multiple tools"""
        findings = []
        
        # GitLeaks scan
        cmd = ["gitleaks", "detect", "--source", directory, "--no-git", "--report-format", "json", "--report-path", "/tmp/gitleaks.json"]
        result = await self.run_command_async(cmd)
        
        if os.path.exists("/tmp/gitleaks.json"):
            try:
                with open("/tmp/gitleaks.json", 'r') as f:
                    data = json.load(f)
                    for finding in data:
                        findings.append({
                            'tool': 'gitleaks',
                            'type': 'secret',
                            'severity': 'high',
                            'title': f"Potential {finding.get('RuleID', 'secret')} found",
                            'file': finding.get('File', ''),
                            'line': finding.get('StartLine', 0),
                            'secret_type': finding.get('RuleID', ''),
                            'match': finding.get('Match', '')[:100] + '...' if len(finding.get('Match', '')) > 100 else finding.get('Match', ''),
                            'commit': finding.get('Commit', ''),
                            'author': finding.get('Author', '')
                        })
                os.remove("/tmp/gitleaks.json")
            except:
                pass
        
        # TruffleHog v3 scan
        cmd = ["trufflehog", "filesystem", directory, "--json", "--no-verification"]
        result = await self.run_command_async(cmd)
        
        if result['stdout']:
            for line in result['stdout'].strip().split('\n'):
                if line:
                    try:
                        finding = json.loads(line)
                        findings.append({
                            'tool': 'trufflehog',
                            'type': 'secret',
                            'severity': 'high',
                            'title': f"Secret found: {finding.get('DetectorName', 'Unknown')}",
                            'file': finding.get('SourceMetadata', {}).get('Data', {}).get('Filesystem', {}).get('file', ''),
                            'line': finding.get('SourceMetadata', {}).get('Data', {}).get('Filesystem', {}).get('line', 0),
                            'verified': finding.get('Verified', False),
                            'secret_type': finding.get('DetectorName', ''),
                            'raw_secret': finding.get('Raw', '')[:50] + '...' if len(finding.get('Raw', '')) > 50 else finding.get('Raw', '')
                        })
                    except:
                        pass
        
        # detect-secrets scan
        cmd = ["detect-secrets", "scan", directory]
        result = await self.run_command_async(cmd)
        
        if result['stdout']:
            try:
                data = json.loads(result['stdout'])
                for file_path, secrets in data.get('results', {}).items():
                    for secret in secrets:
                        findings.append({
                            'tool': 'detect-secrets',
                            'type': 'secret',
                            'severity': 'high',
                            'title': f"Secret detected: {secret.get('type', 'Unknown type')}",
                            'file': file_path,
                            'line': secret.get('line_number', 0),
                            'secret_type': secret.get('type', ''),
                            'hashed_secret': secret.get('hashed_secret', '')
                        })
            except:
                pass
        
        return findings
    
    async def scan_dependencies(self, directory: str, project_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Scan for vulnerable dependencies"""
        findings = []
        
        # Python dependencies with Safety
        if 'python' in project_info['languages'] and os.path.exists(os.path.join(directory, 'requirements.txt')):
            cmd = ["safety", "check", "--json", "-r", os.path.join(directory, 'requirements.txt')]
            result = await self.run_command_async(cmd)
            
            if result['stdout']:
                try:
                    data = json.loads(result['stdout'])
                    for vuln in data.get('vulnerabilities', []):
                        findings.append({
                            'tool': 'safety',
                            'type': 'dependency',
                            'severity': 'high' if vuln.get('severity', '').lower() == 'high' else 'medium',
                            'title': f"Vulnerable dependency: {vuln.get('package_name', '')} {vuln.get('analyzed_version', '')}",
                            'description': vuln.get('description', ''),
                            'cve': vuln.get('cve', ''),
                            'fixed_versions': vuln.get('fixed_versions', []),
                            'affected_versions': vuln.get('affected_versions', '')
                        })
                except:
                    pass
        
        # Node.js dependencies with npm audit
        if 'javascript' in project_info['languages'] and os.path.exists(os.path.join(directory, 'package.json')):
            cmd = ["npm", "audit", "--json"]
            result = await self.run_command_async(cmd, timeout=120)
            
            if result['stdout']:
                try:
                    data = json.loads(result['stdout'])
                    for key, vuln in data.get('vulnerabilities', {}).items():
                        findings.append({
                            'tool': 'npm-audit',
                            'type': 'dependency',
                            'severity': vuln.get('severity', 'medium'),
                            'title': f"Vulnerable dependency: {vuln.get('name', '')}",
                            'description': vuln.get('title', ''),
                            'cve': vuln.get('cves', []),
                            'range': vuln.get('range', ''),
                            'fixed_in': vuln.get('fixAvailable', {}).get('version', 'No fix available')
                        })
                except:
                    pass
        
        # Java dependencies with OWASP Dependency Check
        if 'java' in project_info['languages']:
            # This would require proper setup of OWASP DC
            pass
        
        # General vulnerability scanning with Grype
        cmd = ["grype", "dir:" + directory, "-o", "json"]
        result = await self.run_command_async(cmd, timeout=180)
        
        if result['stdout']:
            try:
                data = json.loads(result['stdout'])
                for match in data.get('matches', []):
                    vuln = match.get('vulnerability', {})
                    findings.append({
                        'tool': 'grype',
                        'type': 'dependency',
                        'severity': vuln.get('severity', 'medium').lower(),
                        'title': f"Vulnerable package: {match.get('artifact', {}).get('name', '')} {match.get('artifact', {}).get('version', '')}",
                        'description': vuln.get('description', ''),
                        'cve': vuln.get('id', ''),
                        'cvss': vuln.get('cvss', []),
                        'fix': vuln.get('fix', {}).get('versions', [])
                    })
            except:
                pass
        
        return findings
    
    async def scan_infrastructure(self, directory: str) -> List[Dict[str, Any]]:
        """Scan infrastructure as code"""
        findings = []
        
        # Checkov for Terraform, CloudFormation, Kubernetes, etc.
        cmd = ["checkov", "-d", directory, "--output", "json"]
        result = await self.run_command_async(cmd, timeout=180)
        
        if result['stdout']:
            try:
                data = json.loads(result['stdout'])
                for check_type in ['failed_checks', 'failed_policies']:
                    for check in data.get('results', {}).get(check_type, []):
                        findings.append({
                            'tool': 'checkov',
                            'type': 'infrastructure',
                            'severity': 'high' if check.get('severity', '').upper() in ['HIGH', 'CRITICAL'] else 'medium',
                            'title': check.get('check_name', 'Infrastructure issue'),
                            'file': check.get('file_path', ''),
                            'line': check.get('file_line_range', [0])[0] if check.get('file_line_range') else 0,
                            'resource': check.get('resource', ''),
                            'check_id': check.get('check_id', ''),
                            'guideline': check.get('guideline', '')
                        })
            except:
                pass
        
        # Trivy for container scanning
        if any(f in os.listdir(directory) for f in ['Dockerfile', 'docker-compose.yml']):
            cmd = ["trivy", "fs", "--security-checks", "vuln,config", "--format", "json", directory]
            result = await self.run_command_async(cmd, timeout=180)
            
            if result['stdout']:
                try:
                    data = json.loads(result['stdout'])
                    for result_item in data.get('Results', []):
                        for vuln in result_item.get('Vulnerabilities', []):
                            findings.append({
                                'tool': 'trivy',
                                'type': 'infrastructure',
                                'severity': vuln.get('Severity', 'medium').lower(),
                                'title': f"Container vulnerability: {vuln.get('Title', vuln.get('VulnerabilityID', ''))}",
                                'description': vuln.get('Description', ''),
                                'cve': vuln.get('VulnerabilityID', ''),
                                'package': vuln.get('PkgName', ''),
                                'version': vuln.get('InstalledVersion', ''),
                                'fixed_version': vuln.get('FixedVersion', 'No fix available')
                            })
                except:
                    pass
        
        return findings
    
    async def scan_code_quality(self, directory: str, project_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Scan for code quality issues"""
        findings = []
        
        # Language-specific linters
        if 'python' in project_info['languages']:
            # Pylint
            cmd = ["pylint", "--output-format=json", "--recursive=y", directory]
            result = await self.run_command_async(cmd, timeout=120)
            
            if result['stdout']:
                try:
                    data = json.loads(result['stdout'])
                    for issue in data:
                        if issue.get('type') in ['error', 'warning']:
                            findings.append({
                                'tool': 'pylint',
                                'type': 'code_quality',
                                'severity': 'high' if issue.get('type') == 'error' else 'medium',
                                'title': issue.get('message', ''),
                                'file': issue.get('path', ''),
                                'line': issue.get('line', 0),
                                'column': issue.get('column', 0),
                                'symbol': issue.get('symbol', ''),
                                'category': issue.get('category', '')
                            })
                except:
                    pass
        
        if 'javascript' in project_info['languages']:
            # ESLint with security plugin
            eslintrc = {
                "extends": ["eslint:recommended"],
                "plugins": ["security"],
                "rules": {
                    "security/detect-object-injection": "warn",
                    "security/detect-non-literal-regexp": "warn",
                    "security/detect-unsafe-regex": "error",
                    "security/detect-eval-with-expression": "error"
                }
            }
            
            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
                json.dump(eslintrc, f)
                eslintrc_path = f.name
            
            cmd = ["eslint", "--format=json", "--config", eslintrc_path, directory]
            result = await self.run_command_async(cmd, timeout=120)
            
            if result['stdout']:
                try:
                    data = json.loads(result['stdout'])
                    for file_result in data:
                        for msg in file_result.get('messages', []):
                            findings.append({
                                'tool': 'eslint',
                                'type': 'code_quality',
                                'severity': 'high' if msg.get('severity') == 2 else 'medium',
                                'title': msg.get('message', ''),
                                'file': file_result.get('filePath', ''),
                                'line': msg.get('line', 0),
                                'column': msg.get('column', 0),
                                'rule': msg.get('ruleId', '')
                            })
                except:
                    pass
            
            os.unlink(eslintrc_path)
        
        return findings
    
    async def scan_mobile_specific(self, directory: str, project_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Mobile app specific scanning"""
        findings = []
        
        if 'android' in project_info['project_types']:
            # MobSF for Android
            cmd = ["mobsfscan", "--json", "-t", "android", directory]
            result = await self.run_command_async(cmd)
            
            if result['stdout']:
                try:
                    data = json.loads(result['stdout'])
                    for issue_type, issues in data.get('results', {}).items():
                        for file_path, file_issues in issues.items():
                            for issue in file_issues:
                                findings.append({
                                    'tool': 'mobsfscan',
                                    'type': 'mobile_security',
                                    'severity': issue.get('severity', 'medium').lower(),
                                    'title': issue.get('description', 'Mobile security issue'),
                                    'file': file_path,
                                    'rule': issue.get('rule', ''),
                                    'owasp_mobile': issue.get('owasp-mobile', ''),
                                    'cwe': issue.get('cwe', '')
                                })
                except:
                    pass
        
        if 'ios' in project_info['project_types']:
            # MobSF for iOS
            cmd = ["mobsfscan", "--json", "-t", "ios", directory]
            result = await self.run_command_async(cmd)
            # Similar parsing as Android
        
        return findings
    
    async def run_comprehensive_scan(self, directory: str) -> Dict[str, Any]:
        """Run comprehensive security scan on directory"""
        logger.info(f"Starting comprehensive scan of: {directory}")
        
        # Detect project type and technologies
        project_info = await self.detect_project_type(directory)
        logger.info(f"Detected project info: {project_info}")
        
        # Run all relevant scanners in parallel
        scan_tasks = [
            self.scan_with_semgrep(directory),
            self.scan_secrets_comprehensive(directory),
            self.scan_dependencies(directory, project_info),
            self.scan_infrastructure(directory),
            self.scan_code_quality(directory, project_info)
        ]
        
        if project_info['has_mobile']:
            scan_tasks.append(self.scan_mobile_specific(directory, project_info))
        
        # Execute all scans in parallel
        results = await asyncio.gather(*scan_tasks, return_exceptions=True)
        
        # Combine results
        all_findings = []
        for i, result in enumerate(results):
            if isinstance(result, list):
                all_findings.extend(result)
            elif isinstance(result, Exception):
                logger.error(f"Scan task {i} failed: {result}")
        
        # Categorize findings
        categorized = {
            'vulnerabilities': [],
            'secrets': [],
            'dependencies': [],
            'code_quality': [],
            'infrastructure': [],
            'mobile_security': [],
            'compliance': []
        }
        
        severity_counts = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0
        }
        
        for finding in all_findings:
            finding_type = finding.get('type', 'vulnerabilities')
            if finding_type == 'secret':
                categorized['secrets'].append(finding)
            elif finding_type == 'dependency':
                categorized['dependencies'].append(finding)
            elif finding_type == 'code_quality':
                categorized['code_quality'].append(finding)
            elif finding_type == 'infrastructure':
                categorized['infrastructure'].append(finding)
            elif finding_type == 'mobile_security':
                categorized['mobile_security'].append(finding)
            else:
                categorized['vulnerabilities'].append(finding)
            
            # Count severities
            severity = finding.get('severity', 'medium').lower()
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        # Generate summary
        summary = {
            'total_findings': len(all_findings),
            'severity_breakdown': severity_counts,
            'categories': {k: len(v) for k, v in categorized.items()},
            'project_info': project_info,
            'scan_timestamp': os.environ.get('SCAN_TIMESTAMP', 'N/A')
        }
        
        return {
            'summary': summary,
            'findings': categorized,
            'all_findings': all_findings,
            'project_info': project_info
        }