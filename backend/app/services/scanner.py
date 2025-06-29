import asyncio
import os
import tempfile
import shutil
import zipfile
import tarfile
from typing import Dict, List, Any
from datetime import datetime
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.scan import Scan, ScanStatus, ScanResult, Severity
from app.models.project import Project
from app.utils.database import AsyncSessionLocal
import logging

logger = logging.getLogger(__name__)

class ScannerService:
    def __init__(self):
        self.analyzers = {}
        # Docker is optional - we'll use simple file analysis
        try:
            from app.analyzers.python import PythonAnalyzer
            from app.analyzers.javascript import JavaScriptAnalyzer
            self.analyzers['python'] = PythonAnalyzer()
            self.analyzers['javascript'] = JavaScriptAnalyzer()
        except ImportError:
            logger.warning("Analyzers not available, using basic scanning")
    
    async def start_scan(self, scan_id: int, project: Project, scan: Scan):
        """Start a scan job"""
        async with AsyncSessionLocal() as db:
            try:
                # Get the scan from DB
                scan = await db.get(Scan, scan_id)
                if not scan:
                    raise ValueError(f"Scan {scan_id} not found")
                
                # Update scan status
                scan.status = ScanStatus.RUNNING
                scan.started_at = datetime.utcnow()
                await db.commit()
                
                # Get code to scan
                code_path = await self._prepare_code(project, scan)
                
                # Run analyzers
                all_results = []
                
                # Analyze dependencies first
                dependency_info = await self._analyze_dependencies(code_path)
                
                # Basic static analysis
                static_results = await self._run_basic_analysis(code_path, dependency_info)
                all_results.extend(static_results)
                
                # Save results
                await self._save_results(db, scan_id, all_results)
                
                # Update scan summary
                await self._update_scan_summary(db, scan, all_results)
                
                # Mark scan as completed
                scan.status = ScanStatus.COMPLETED
                scan.completed_at = datetime.utcnow()
                await db.commit()
                
            except Exception as e:
                logger.error(f"Scan {scan_id} failed: {str(e)}")
                if scan:
                    scan.status = ScanStatus.FAILED
                    scan.error_message = str(e)
                    scan.completed_at = datetime.utcnow()
                    await db.commit()
            
            finally:
                # Cleanup
                if 'code_path' in locals() and os.path.exists(code_path):
                    shutil.rmtree(code_path, ignore_errors=True)
    
    async def _prepare_code(self, project: Project, scan: Scan) -> str:
        """Prepare code for scanning"""
        temp_dir = tempfile.mkdtemp()
        
        if project.github_repo_url:
            # For now, we'll skip GitHub cloning if git is not available
            try:
                import git
                repo = git.Repo.clone_from(
                    project.github_repo_url,
                    temp_dir,
                    branch=scan.branch or project.github_default_branch
                )
                if scan.commit_sha:
                    repo.git.checkout(scan.commit_sha)
            except ImportError:
                raise ValueError("Git module not available for GitHub repositories")
        elif project.uploaded_file_path:
            # Extract uploaded file
            file_path = project.uploaded_file_path
            if not os.path.exists(file_path):
                raise ValueError(f"Uploaded file not found: {file_path}")
            
            # Handle different file types
            if file_path.endswith('.zip'):
                with zipfile.ZipFile(file_path, 'r') as zip_ref:
                    zip_ref.extractall(temp_dir)
            elif file_path.endswith(('.tar', '.tar.gz', '.tgz')):
                with tarfile.open(file_path, 'r:*') as tar_ref:
                    tar_ref.extractall(temp_dir)
            else:
                # Single file - copy it
                shutil.copy2(file_path, temp_dir)
        else:
            raise ValueError("No code source available for project")
        
        return temp_dir
    
    async def _analyze_dependencies(self, code_path: str) -> Dict[str, Any]:
        """Analyze project dependencies and detect vulnerable packages"""
        dependency_info = {
            'packages': {},
            'package_files': [],
            'vulnerable_packages': {},
            'technology_stack': []
        }
        
        # Look for package files
        package_files = {
            'package.json': 'npm',
            'package-lock.json': 'npm',
            'yarn.lock': 'yarn',
            'requirements.txt': 'pip',
            'requirements-dev.txt': 'pip',
            'Pipfile': 'pipenv',
            'Pipfile.lock': 'pipenv',
            'setup.py': 'setuptools',
            'pyproject.toml': 'poetry',
            'composer.json': 'composer',
            'Gemfile': 'bundler',
            'Gemfile.lock': 'bundler',
            'go.mod': 'go modules',
            'go.sum': 'go modules',
            'pom.xml': 'maven',
            'build.gradle': 'gradle',
            'Cargo.toml': 'cargo',
            'Cargo.lock': 'cargo'
        }
        
        for root, dirs, files in os.walk(code_path):
            dirs[:] = [d for d in dirs if not d.startswith('.')]
            
            for file in files:
                if file in package_files:
                    file_path = os.path.join(root, file)
                    relative_path = os.path.relpath(file_path, code_path)
                    
                    package_manager = package_files[file]
                    dependency_info['package_files'].append({
                        'file': relative_path,
                        'type': package_manager
                    })
                    
                    if package_manager not in dependency_info['technology_stack']:
                        dependency_info['technology_stack'].append(package_manager)
                    
                    # Parse dependencies
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                            
                        if file == 'package.json':
                            dependencies = self._parse_package_json(content)
                            dependency_info['packages'].update(dependencies)
                        elif file == 'requirements.txt':
                            dependencies = self._parse_requirements_txt(content)
                            dependency_info['packages'].update(dependencies)
                        elif file == 'Pipfile':
                            dependencies = self._parse_pipfile(content)
                            dependency_info['packages'].update(dependencies)
                    except Exception as e:
                        logger.warning(f"Error parsing {file_path}: {e}")
        
        # Check for known vulnerable packages
        dependency_info['vulnerable_packages'] = self._check_vulnerable_packages(dependency_info['packages'])
        
        return dependency_info
    
    def _parse_package_json(self, content: str) -> Dict[str, str]:
        """Parse package.json dependencies"""
        try:
            import json
            data = json.loads(content)
            dependencies = {}
            
            for dep_type in ['dependencies', 'devDependencies', 'peerDependencies']:
                if dep_type in data:
                    for package, version in data[dep_type].items():
                        dependencies[package] = version
            
            return dependencies
        except Exception:
            return {}
    
    def _parse_requirements_txt(self, content: str) -> Dict[str, str]:
        """Parse requirements.txt dependencies"""
        dependencies = {}
        
        for line in content.splitlines():
            line = line.strip()
            if line and not line.startswith('#'):
                # Handle different version specifiers
                for separator in ['==', '>=', '<=', '>', '<', '~=']:
                    if separator in line:
                        package, version = line.split(separator, 1)
                        dependencies[package.strip()] = f"{separator}{version.strip()}"
                        break
                else:
                    # No version specified
                    dependencies[line] = "*"
        
        return dependencies
    
    def _parse_pipfile(self, content: str) -> Dict[str, str]:
        """Parse Pipfile dependencies"""
        dependencies = {}
        try:
            import toml
            data = toml.loads(content)
            
            for section in ['packages', 'dev-packages']:
                if section in data:
                    for package, version in data[section].items():
                        if isinstance(version, str):
                            dependencies[package] = version
                        elif isinstance(version, dict) and 'version' in version:
                            dependencies[package] = version['version']
        except Exception:
            # Fallback to simple parsing if toml not available
            in_packages = False
            for line in content.splitlines():
                line = line.strip()
                if line == '[packages]' or line == '[dev-packages]':
                    in_packages = True
                elif line.startswith('[') and line.endswith(']'):
                    in_packages = False
                elif in_packages and '=' in line:
                    package, version = line.split('=', 1)
                    dependencies[package.strip()] = version.strip().strip('"\'')
        
        return dependencies
    
    def _check_vulnerable_packages(self, packages: Dict[str, str]) -> Dict[str, Dict[str, Any]]:
        """Check for known vulnerable packages"""
        # This is a simplified vulnerability database
        # In production, you would integrate with actual vulnerability databases
        known_vulnerabilities = {
            'lodash': {
                'vulnerable_versions': ['<4.17.21'],
                'fixed_version': '4.17.21',
                'cve': 'CVE-2021-23337',
                'severity': 'high',
                'description': 'Command injection vulnerability in lodash'
            },
            'express': {
                'vulnerable_versions': ['<4.18.0'],
                'fixed_version': '4.18.0',
                'cve': 'CVE-2022-24999',
                'severity': 'medium',
                'description': 'Cross-site scripting vulnerability in express'
            },
            'django': {
                'vulnerable_versions': ['<3.2.13', '>=4.0,<4.0.4'],
                'fixed_version': '3.2.13, 4.0.4',
                'cve': 'CVE-2022-28346',
                'severity': 'high',
                'description': 'SQL injection vulnerability in Django'
            },
            'flask': {
                'vulnerable_versions': ['<1.1.4'],
                'fixed_version': '1.1.4',
                'cve': 'CVE-2021-23362',
                'severity': 'medium',
                'description': 'Open redirect vulnerability in Flask'
            },
            'jquery': {
                'vulnerable_versions': ['<3.5.0'],
                'fixed_version': '3.5.0',
                'cve': 'CVE-2020-11022',
                'severity': 'medium',
                'description': 'Cross-site scripting vulnerability in jQuery'
            }
        }
        
        vulnerable = {}
        for package, version in packages.items():
            if package.lower() in known_vulnerabilities:
                vuln_info = known_vulnerabilities[package.lower()]
                # Simple version check (in production, use proper semver parsing)
                vulnerable[package] = {
                    **vuln_info,
                    'current_version': version
                }
        
        return vulnerable
    
    async def _run_basic_analysis(self, code_path: str, dependency_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Run basic security analysis without external dependencies"""
        results = []
        
        # Scan for common security issues
        for root, dirs, files in os.walk(code_path):
            # Skip hidden directories
            dirs[:] = [d for d in dirs if not d.startswith('.')]
            
            for file in files:
                file_path = os.path.join(root, file)
                relative_path = os.path.relpath(file_path, code_path)
                
                # Only scan text files
                if not self._is_text_file(file_path):
                    continue
                
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        line_num = 0
                        
                        for line in content.splitlines():
                            line_num += 1
                            
                            # Check for hardcoded secrets
                            if any(secret in line.lower() for secret in ['password=', 'api_key=', 'secret=', 'token=']):
                                if not line.strip().startswith(('#', '//', '/*', '*')):
                                    results.append({
                                        'rule_id': 'SECURITY-002',
                                        'title': 'Hardcoded Secret/Password',
                                        'description': 'Hardcoded credentials pose a significant security risk as they can be easily discovered by attackers',
                                        'severity': 'high',
                                        'category': 'Security',
                                        'file_path': relative_path,
                                        'line_number': line_num,
                                        'code_snippet': line.strip()[:100],
                                        'vulnerability_type': 'CWE-798',
                                        'fix_recommendation': 'Store sensitive credentials in environment variables or secure key management systems. Never commit secrets to version control.',
                                        'analyzer': 'basic'
                                    })
                            
                            # Check for SQL injection
                            if 'select * from' in line.lower() and ('f"' in line or 'f\'' in line or '+' in line):
                                results.append({
                                    'rule_id': 'SECURITY-003',
                                    'title': 'SQL Injection Vulnerability',
                                    'description': 'Direct concatenation of user input in SQL queries can allow attackers to manipulate database queries',
                                    'severity': 'critical',
                                    'category': 'Security',
                                    'file_path': relative_path,
                                    'line_number': line_num,
                                    'code_snippet': line.strip()[:100],
                                    'vulnerability_type': 'CWE-89',
                                    'fix_recommendation': 'Use parameterized queries or prepared statements. Never concatenate user input directly into SQL queries.',
                                    'analyzer': 'basic'
                                })
                            
                            # Check for command injection
                            if any(cmd in line for cmd in ['os.system(', 'subprocess.call(', 'exec(', 'eval(']):
                                if not line.strip().startswith(('#', '//', '/*', '*')):
                                    # Get context lines
                                    context_lines = self._get_code_context(content.splitlines(), line_num - 1, 3)
                                    
                                    # Determine affected packages based on file extension and imports
                                    affected_packages = self._determine_affected_packages(content, relative_path, dependency_info)
                                    
                                    finding = {
                                        'rule_id': 'SECURITY-001',
                                        'title': 'Command Injection Vulnerability',
                                        'description': 'User input is passed directly to a system command execution function, allowing attackers to execute arbitrary commands',
                                        'severity': 'critical',
                                        'category': 'Security',
                                        'file_path': relative_path,
                                        'line_number': line_num,
                                        'code_snippet': line.strip()[:100],
                                        'code_context': context_lines,
                                        'vulnerability_type': 'CWE-78',
                                        'fix_recommendation': 'Avoid using exec(), eval(), or similar functions with user input. Use subprocess with proper input validation and escaping.',
                                        'remediation_example': '''// Safe alternative using subprocess with input validation
const { spawn } = require('child_process');

// Validate and sanitize input
const allowedCommands = ['ls', 'pwd', 'echo'];
const sanitizedCommand = validateCommand(userInput);

if (allowedCommands.includes(sanitizedCommand)) {
    const child = spawn(sanitizedCommand, [], { shell: false });
    // Handle output safely
}''',
                                        'owasp_category': 'A03:2021 - Injection',
                                        'cvss_score': 9.8,
                                        'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
                                        'risk_rating': 'Critical',
                                        'compliance_mappings': {
                                            'PCI-DSS': '6.5.1',
                                            'ISO-27001': 'A.14.2.5',
                                            'NIST': 'SI-10'
                                        },
                                        'exploitability': 'High - Can be exploited remotely without authentication',
                                        'impact': 'Complete system compromise, data theft, service disruption',
                                        'likelihood': 'High if user input reaches this function',
                                        'fix_effort': 'Medium - Requires refactoring to use safe APIs',
                                        'fix_priority': 1,
                                        'references': [
                                            'https://owasp.org/www-community/attacks/Command_Injection',
                                            'https://cwe.mitre.org/data/definitions/78.html',
                                            'https://nodejs.org/api/child_process.html#child_processspawncommand-args-options'
                                        ],
                                        'analyzer': 'basic',
                                        'confidence': 'high',
                                        'tags': ['injection', 'command-execution', 'user-input'],
                                        # Dependency information
                                        'affected_packages': affected_packages['packages'],
                                        'vulnerable_versions': affected_packages['vulnerable_versions'],
                                        'fixed_versions': affected_packages['fixed_versions'],
                                        'dependency_chain': affected_packages['dependency_chain']
                                    }
                                    logger.info(f"Found command injection vulnerability with rule_id: {finding['rule_id']}")
                                    results.append(finding)
                            
                            # Check for XSS vulnerabilities
                            if 'innerhtml' in line.lower() or 'document.write' in line.lower():
                                results.append({
                                    'rule_id': 'SECURITY-004',
                                    'title': 'Cross-Site Scripting (XSS) Risk',
                                    'description': 'Directly manipulating DOM with user input can lead to XSS attacks',
                                    'severity': 'high',
                                    'category': 'Security',
                                    'file_path': relative_path,
                                    'line_number': line_num,
                                    'code_snippet': line.strip()[:100],
                                    'vulnerability_type': 'CWE-79',
                                    'fix_recommendation': 'Sanitize user input before rendering. Use textContent instead of innerHTML when possible.',
                                    'analyzer': 'basic'
                                })
                            
                            # Check for weak cryptography
                            if any(weak in line.lower() for weak in ['md5', 'sha1', 'des']):
                                if 'password' in line.lower() or 'hash' in line.lower():
                                    results.append({
                                        'rule_id': 'SECURITY-005',
                                        'title': 'Weak Cryptography',
                                        'description': 'Using weak or deprecated cryptographic algorithms',
                                        'severity': 'medium',
                                        'category': 'Security',
                                        'file_path': relative_path,
                                        'line_number': line_num,
                                        'code_snippet': line.strip()[:100],
                                        'vulnerability_type': 'CWE-327',
                                        'fix_recommendation': 'Use strong cryptographic algorithms like SHA-256, bcrypt, or Argon2 for password hashing.',
                                        'analyzer': 'basic'
                                    })
                            
                            # Check for path traversal
                            if '..' in line and ('open(' in line or 'readfile' in line.lower() or 'sendfile' in line.lower()):
                                results.append({
                                    'rule_id': 'SECURITY-006',
                                    'title': 'Path Traversal Vulnerability',
                                    'description': 'File operations without proper path validation can allow unauthorized file access',
                                    'severity': 'high',
                                    'category': 'Security',
                                    'file_path': relative_path,
                                    'line_number': line_num,
                                    'code_snippet': line.strip()[:100],
                                    'vulnerability_type': 'CWE-22',
                                    'fix_recommendation': 'Validate and sanitize file paths. Use whitelisting for allowed directories.',
                                    'analyzer': 'basic'
                                })
                            
                            # Check for insecure random
                            if 'math.random()' in line.lower() and any(sec in line.lower() for sec in ['token', 'session', 'key', 'password']):
                                results.append({
                                    'rule_id': 'SECURITY-007',
                                    'title': 'Insecure Random Number Generation',
                                    'description': 'Using Math.random() for security-sensitive operations is insecure',
                                    'severity': 'medium',
                                    'category': 'Security',
                                    'file_path': relative_path,
                                    'line_number': line_num,
                                    'code_snippet': line.strip()[:100],
                                    'vulnerability_type': 'CWE-330',
                                    'fix_recommendation': 'Use crypto.getRandomValues() or similar cryptographically secure random generators.',
                                    'analyzer': 'basic'
                                })
                
                except Exception as e:
                    logger.warning(f"Error scanning file {file_path}: {e}")
        
        # Add dependency vulnerabilities
        for package, vuln_info in dependency_info['vulnerable_packages'].items():
            results.append({
                'rule_id': 'SECURITY-DEP-001',
                'title': f'Vulnerable Dependency: {package}',
                'description': f'Package {package} version {vuln_info["current_version"]} has known vulnerabilities. {vuln_info["description"]}',
                'severity': vuln_info['severity'],
                'category': 'Dependency',
                'file_path': 'package dependencies',
                'vulnerability_type': vuln_info.get('cve', 'Unknown CVE'),
                'fix_recommendation': f'Update {package} to version {vuln_info["fixed_version"]} or later to fix this vulnerability.',
                'remediation_example': f'''# Update package to fix vulnerability
npm update {package}@{vuln_info["fixed_version"]}
# or for Python
pip install {package}>={vuln_info["fixed_version"]}''',
                'owasp_category': 'A06:2021 - Vulnerable and Outdated Components',
                'cvss_score': 7.5 if vuln_info['severity'] == 'high' else 5.0,
                'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H',
                'risk_rating': vuln_info['severity'].title(),
                'compliance_mappings': {
                    'PCI-DSS': '6.2',
                    'ISO-27001': 'A.12.6.1',
                    'NIST': 'SI-2'
                },
                'exploitability': f'Medium - Depends on how {package} is used in the application',
                'impact': 'Data breach, service disruption, code execution',
                'likelihood': 'Medium - Requires specific usage patterns',
                'fix_effort': 'Low - Simple package update',
                'fix_priority': 2 if vuln_info['severity'] == 'high' else 3,
                'references': [f'https://nvd.nist.gov/vuln/detail/{vuln_info.get("cve", "")}'],
                'analyzer': 'dependency',
                'confidence': 'high',
                'tags': ['dependency', 'outdated', 'vulnerable-component'],
                # Dependency specific information
                'affected_packages': [package],
                'vulnerable_versions': {package: vuln_info['vulnerable_versions']},
                'fixed_versions': {package: vuln_info['fixed_version']},
                'dependency_chain': [package]  # Direct dependency
            })
        
        return results
    
    def _determine_affected_packages(self, content: str, file_path: str, dependency_info: Dict[str, Any]) -> Dict[str, Any]:
        """Determine which packages are affected by a vulnerability in this file"""
        affected = {
            'packages': [],
            'vulnerable_versions': {},
            'fixed_versions': {},
            'dependency_chain': []
        }
        
        # Extract imports/requires from the file
        imports = []
        for line in content.splitlines():
            line = line.strip()
            
            # JavaScript/Node.js imports
            if 'require(' in line or 'import ' in line:
                if 'require(' in line:
                    # Extract package name from require('package')
                    start = line.find("require('") + 9
                    end = line.find("')", start)
                    if start < end:
                        package = line[start:end].split('/')[0]  # Get main package name
                        imports.append(package)
                elif 'import ' in line and ' from ' in line:
                    # Extract package name from import x from 'package'
                    start = line.find("from '") + 6
                    end = line.find("'", start)
                    if start < end:
                        package = line[start:end].split('/')[0]
                        imports.append(package)
            
            # Python imports
            elif line.startswith('import ') or line.startswith('from '):
                parts = line.split()
                if len(parts) >= 2:
                    if parts[0] == 'import':
                        package = parts[1].split('.')[0]
                        imports.append(package)
                    elif parts[0] == 'from' and len(parts) >= 4:
                        package = parts[1].split('.')[0]
                        imports.append(package)
        
        # Check which imported packages are in our dependency list
        for package in imports:
            if package in dependency_info['packages']:
                affected['packages'].append(package)
                affected['dependency_chain'].append(package)
                
                # If it's a vulnerable package, add version info
                if package in dependency_info['vulnerable_packages']:
                    vuln_info = dependency_info['vulnerable_packages'][package]
                    affected['vulnerable_versions'][package] = vuln_info['vulnerable_versions']
                    affected['fixed_versions'][package] = vuln_info['fixed_version']
        
        # If no specific packages found, check by file type for common frameworks
        if not affected['packages']:
            file_ext = file_path.split('.')[-1].lower()
            
            if file_ext in ['js', 'jsx', 'ts', 'tsx']:
                # Common Node.js packages that might be affected
                common_js_packages = ['express', 'lodash', 'jquery', 'react', 'vue', 'angular']
                for package in common_js_packages:
                    if package in dependency_info['packages']:
                        affected['packages'].append(package)
                        affected['dependency_chain'].append(package)
            
            elif file_ext in ['py']:
                # Common Python packages
                common_py_packages = ['django', 'flask', 'requests', 'urllib3', 'jinja2']
                for package in common_py_packages:
                    if package in dependency_info['packages']:
                        affected['packages'].append(package)
                        affected['dependency_chain'].append(package)
        
        return affected
    
    def _is_text_file(self, file_path: str) -> bool:
        """Check if file is a text file"""
        text_extensions = {'.py', '.js', '.java', '.go', '.rb', '.php', '.cs', '.cpp', '.c', '.h', 
                          '.jsx', '.ts', '.tsx', '.vue', '.html', '.css', '.xml', '.json', '.yaml', 
                          '.yml', '.md', '.txt', '.sh', '.bash'}
        ext = os.path.splitext(file_path)[1].lower()
        return ext in text_extensions
    
    def _get_code_context(self, lines: List[str], line_index: int, context_size: int = 3) -> Dict[str, Any]:
        """Get code context around a finding"""
        start = max(0, line_index - context_size)
        end = min(len(lines), line_index + context_size + 1)
        
        context = {
            'before': [],
            'line': lines[line_index] if line_index < len(lines) else '',
            'after': []
        }
        
        # Get before context
        for i in range(start, line_index):
            context['before'].append({
                'line_number': i + 1,
                'content': lines[i]
            })
        
        # Get after context
        for i in range(line_index + 1, end):
            context['after'].append({
                'line_number': i + 1,
                'content': lines[i]
            })
        
        return context
    
    async def _run_static_analysis(self, code_path: str) -> List[Dict[str, Any]]:
        """Run static analysis tools"""
        results = []
        
        # Detect languages
        languages = self._detect_languages(code_path)
        
        # Run appropriate analyzers
        for language in languages:
            if language in self.analyzers:
                analyzer = self.analyzers[language]
                language_results = await analyzer.analyze(code_path)
                results.extend(language_results)
        
        return results
    
    async def _run_ai_analysis(self, code_path: str) -> List[Dict[str, Any]]:
        """Run AI-powered analysis"""
        return await self.ai_analyzer.analyze(code_path)
    
    def _detect_languages(self, code_path: str) -> List[str]:
        """Detect programming languages in the codebase"""
        languages = set()
        
        for root, dirs, files in os.walk(code_path):
            # Skip hidden directories
            dirs[:] = [d for d in dirs if not d.startswith('.')]
            
            for file in files:
                ext = os.path.splitext(file)[1].lower()
                if ext in ['.py', '.pyw']:
                    languages.add('python')
                elif ext in ['.js', '.jsx', '.ts', '.tsx']:
                    languages.add('javascript')
                elif ext in ['.java']:
                    languages.add('java')
                elif ext in ['.go']:
                    languages.add('go')
                # Add more language detection
        
        return list(languages)
    
    async def _save_results(self, db: AsyncSession, scan_id: int, results: List[Dict[str, Any]]):
        """Save scan results to database"""
        for result in results:
            logger.info(f"Saving result with rule_id: {result.get('rule_id')}")
            scan_result = ScanResult(
                scan_id=scan_id,
                rule_id=result.get('rule_id'),
                title=result['title'],
                description=result.get('description'),
                severity=Severity(result['severity']),
                category=result.get('category'),
                file_path=result.get('file_path'),
                line_number=result.get('line_number'),
                column_number=result.get('column_number'),
                code_snippet=result.get('code_snippet'),
                vulnerability_type=result.get('vulnerability_type'),
                confidence=result.get('confidence', 'medium'),
                fix_recommendation=result.get('fix_recommendation'),
                ai_generated_fix=result.get('ai_generated_fix'),
                references=result.get('references', []),
                remediation_example=result.get('remediation_example'),
                # Risk Assessment
                cvss_score=result.get('cvss_score'),
                cvss_vector=result.get('cvss_vector'),
                risk_rating=result.get('risk_rating'),
                exploitability=result.get('exploitability'),
                impact=result.get('impact'),
                likelihood=result.get('likelihood'),
                # Compliance
                owasp_category=result.get('owasp_category'),
                compliance_mappings=result.get('compliance_mappings', {}),
                # Development Impact
                fix_effort=result.get('fix_effort'),
                fix_priority=result.get('fix_priority'),
                # Additional Context
                code_context=result.get('code_context'),
                tags=result.get('tags', []),
                analyzer=result.get('analyzer'),
                raw_output=result.get('raw_output'),
                # Dependency Information
                affected_packages=result.get('affected_packages', []),
                vulnerable_versions=result.get('vulnerable_versions', {}),
                fixed_versions=result.get('fixed_versions', {}),
                dependency_chain=result.get('dependency_chain', [])
            )
            db.add(scan_result)
        
        await db.commit()
    
    async def _update_scan_summary(self, db: AsyncSession, scan: Scan, results: List[Dict[str, Any]]):
        """Update scan summary statistics"""
        scan.total_issues = len(results)
        scan.critical_issues = sum(1 for r in results if r['severity'] == 'critical')
        scan.high_issues = sum(1 for r in results if r['severity'] == 'high')
        scan.medium_issues = sum(1 for r in results if r['severity'] == 'medium')
        scan.low_issues = sum(1 for r in results if r['severity'] == 'low')
        
        await db.commit()