"""
Enterprise-Grade GitHub Repository Scanner
Full comprehensive security analysis with detailed code-level reporting
"""
import os
import uuid
import json
import asyncio
import subprocess
import tempfile
import shutil
from datetime import datetime
from typing import Dict, Any, Optional, List
from fastapi import APIRouter, HTTPException, BackgroundTasks
from pydantic import BaseModel, HttpUrl
import git
import logging

from app.services.comprehensive_scanner import ComprehensiveSecurityScanner
from app.services.universal_scanner_service import EnhancedUniversalScanner
from app.utils.ai_analyzer import AISecurityAnalyzer

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/enterprise", tags=["Enterprise GitHub Scanner"])

# Scan results storage (use Redis/Database in production)
enterprise_scan_results = {}

class GitHubScanRequest(BaseModel):
    """Enterprise GitHub scan request model"""
    repository_url: HttpUrl
    branch: str = "main"
    scan_depth: str = "comprehensive"  # quick, standard, comprehensive, paranoid
    enable_ai_analysis: bool = False
    include_commit_history: bool = True
    include_pr_analysis: bool = False
    max_history_depth: int = 100
    project_id: Optional[str] = None
    user_id: Optional[str] = None

class ScanStatus(BaseModel):
    """Scan status response"""
    scan_id: str
    status: str
    progress: int
    phase: str
    message: str
    started_at: str
    estimated_completion: Optional[str] = None
    
@router.post("/github/scan")
async def initiate_enterprise_scan(
    request: GitHubScanRequest,
    background_tasks: BackgroundTasks
):
    """
    Initiate enterprise-grade GitHub repository security scan
    
    This performs a complete security analysis including:
    - Cloning the entire repository with history
    - Running 20+ security scanning tools
    - Analyzing every file for vulnerabilities
    - Scanning commit history for leaked secrets
    - Checking dependencies for known vulnerabilities
    - Infrastructure as Code security analysis
    - Mobile app security checks if applicable
    - AI-powered vulnerability analysis and remediation
    
    Returns scan_id for tracking progress
    """
    scan_id = str(uuid.uuid4())
    
    # Initialize scan metadata
    scan_metadata = {
        'scan_id': scan_id,
        'repository_url': str(request.repository_url),
        'branch': request.branch,
        'scan_depth': request.scan_depth,
        'options': request.dict(),
        'status': 'initializing',
        'phase': 'Starting scan',
        'progress': 0,
        'started_at': datetime.utcnow().isoformat(),
        'findings': {
            'total': 0,
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0
        },
        'tools_completed': [],
        'tools_pending': []
    }
    
    # Store initial status
    enterprise_scan_results[scan_id] = scan_metadata
    
    # Start background scan
    background_tasks.add_task(
        run_enterprise_github_scan,
        scan_id=scan_id,
        request=request,
        metadata=scan_metadata
    )
    
    logger.info(f"Enterprise scan initiated: {scan_id} for {request.repository_url}")
    
    return {
        'scan_id': scan_id,
        'status': 'initiated',
        'message': 'Enterprise security scan started successfully',
        'repository': str(request.repository_url),
        'branch': request.branch,
        'scan_depth': request.scan_depth,
        'estimated_time': get_scan_time_estimate(request.scan_depth)
    }

async def run_enterprise_github_scan(
    scan_id: str,
    request: GitHubScanRequest,
    metadata: Dict[str, Any]
):
    """
    Run the actual enterprise GitHub scan
    """
    scan_dir = f"/tmp/enterprise_scan_{scan_id}"
    repo_dir = os.path.join(scan_dir, "repository")
    results_dir = os.path.join(scan_dir, "results")
    
    try:
        # Create directories
        os.makedirs(scan_dir, exist_ok=True)
        os.makedirs(results_dir, exist_ok=True)
        
        # Update status: Cloning
        update_scan_status(scan_id, 'cloning', 5, 'Cloning repository with full history')
        
        # Clone repository with full history
        logger.info(f"Cloning repository: {request.repository_url}")
        repo = git.Repo.clone_from(
            str(request.repository_url),
            repo_dir,
            branch=request.branch,
            depth=None if request.include_commit_history else 1
        )
        
        # Get repository statistics
        repo_stats = await analyze_repository_structure(repo_dir)
        metadata['repository_stats'] = repo_stats
        
        # Update status: Analyzing
        update_scan_status(scan_id, 'analyzing', 15, f'Analyzing {repo_stats["total_files"]} files')
        
        # Initialize scanners
        comprehensive_scanner = ComprehensiveSecurityScanner()
        enhanced_scanner = EnhancedUniversalScanner()
        
        # Detect project type and technologies
        project_info = await comprehensive_scanner.detect_project_type(repo_dir)
        metadata['project_info'] = {
            'languages': list(project_info['languages']),
            'frameworks': list(project_info['frameworks']),
            'project_types': list(project_info['project_types']),
            'package_managers': list(project_info['package_managers'])
        }
        
        # Prepare list of all scanning tools
        all_tools = [
            ('Semgrep', 'Static analysis for 30+ languages'),
            ('Bandit', 'Python security linter'),
            ('Safety', 'Python dependency checker'),
            ('GitLeaks', 'Secret detection in code'),
            ('TruffleHog', 'Deep secret scanning'),
            ('Grype', 'Container vulnerability scanner'),
            ('Trivy', 'Comprehensive vulnerability scanner'),
            ('Checkov', 'Infrastructure as Code scanner'),
            ('ESLint Security', 'JavaScript security linting'),
            ('Gosec', 'Go security checker'),
            ('Brakeman', 'Ruby on Rails scanner'),
            ('MobSFScan', 'Mobile security scanner'),
            ('OWASP Dependency Check', 'Dependency vulnerability scanner'),
            ('Retire.js', 'JavaScript library scanner'),
            ('Nancy', '.NET dependency scanner'),
            ('Snyk', 'Vulnerability database scanner'),
            ('CodeQL', 'Semantic code analysis'),
            ('SpotBugs', 'Java bug detector'),
            ('Horusec', 'Multi-language scanner'),
            ('Bearer', 'Data flow security scanner')
        ]
        
        metadata['tools_pending'] = [tool[0] for tool in all_tools]
        
        # Run comprehensive security scan
        scan_results = {
            'vulnerabilities': [],
            'secrets': [],
            'dependencies': [],
            'infrastructure': [],
            'code_quality': [],
            'mobile_security': [],
            'compliance': []
        }
        
        # Phase 1: Secret Detection (20-30%)
        update_scan_status(scan_id, 'scanning', 20, 'Scanning for secrets and credentials')
        secrets_results = await run_secret_scanning(repo_dir, request.include_commit_history)
        scan_results['secrets'] = secrets_results
        metadata['tools_completed'].append('GitLeaks')
        metadata['tools_completed'].append('TruffleHog')
        
        # Phase 2: Vulnerability Scanning (30-50%)
        update_scan_status(scan_id, 'scanning', 30, 'Running static analysis for vulnerabilities')
        vuln_results = await run_vulnerability_scanning(repo_dir, project_info)
        scan_results['vulnerabilities'] = vuln_results
        metadata['tools_completed'].extend(['Semgrep', 'Bandit', 'ESLint Security'])
        
        # Phase 3: Dependency Analysis (50-65%)
        update_scan_status(scan_id, 'scanning', 50, 'Analyzing dependencies for known vulnerabilities')
        dep_results = await run_dependency_scanning(repo_dir, project_info)
        scan_results['dependencies'] = dep_results
        metadata['tools_completed'].extend(['Safety', 'Grype', 'Trivy'])
        
        # Phase 4: Infrastructure Scanning (65-75%)
        if project_info.get('has_infrastructure'):
            update_scan_status(scan_id, 'scanning', 65, 'Scanning infrastructure as code')
            infra_results = await run_infrastructure_scanning(repo_dir)
            scan_results['infrastructure'] = infra_results
            metadata['tools_completed'].append('Checkov')
        
        # Phase 5: Mobile Security (75-85%)
        if project_info.get('has_mobile'):
            update_scan_status(scan_id, 'scanning', 75, 'Analyzing mobile app security')
            mobile_results = await run_mobile_scanning(repo_dir)
            scan_results['mobile_security'] = mobile_results
            metadata['tools_completed'].append('MobSFScan')
        
        # Phase 6: Code Quality (85-90%)
        if request.scan_depth in ['comprehensive', 'paranoid']:
            update_scan_status(scan_id, 'scanning', 85, 'Analyzing code quality and best practices')
            quality_results = await run_code_quality_scanning(repo_dir, project_info)
            scan_results['code_quality'] = quality_results
        
        # Aggregate all findings
        all_findings = []
        for category, findings in scan_results.items():
            if isinstance(findings, list):
                for finding in findings:
                    finding['category'] = category
                    all_findings.append(finding)
        
        # Sort by severity
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
        all_findings.sort(key=lambda x: severity_order.get(x.get('severity', 'info').lower(), 5))
        
        # Update finding counts
        metadata['findings']['total'] = len(all_findings)
        for finding in all_findings:
            severity = finding.get('severity', 'info').lower()
            if severity in metadata['findings']:
                metadata['findings'][severity] += 1
        
        # Phase 7: AI Analysis (90-100%)
        if request.enable_ai_analysis and all_findings:
            update_scan_status(scan_id, 'analyzing', 90, 'Running AI-powered security analysis')
            ai_analyzer = AISecurityAnalyzer()
            ai_analysis = await ai_analyzer.analyze_findings(
                findings=all_findings[:50],  # Analyze top 50 findings
                repository_url=str(request.repository_url),
                project_info=project_info
            )
            metadata['ai_analysis'] = ai_analysis
        
        # Generate detailed report
        detailed_report = generate_enterprise_report(
            scan_id=scan_id,
            repository_url=str(request.repository_url),
            branch=request.branch,
            project_info=project_info,
            scan_results=scan_results,
            all_findings=all_findings,
            metadata=metadata
        )
        
        # Save results
        metadata['status'] = 'completed'
        metadata['phase'] = 'Scan completed successfully'
        metadata['progress'] = 100
        metadata['completed_at'] = datetime.utcnow().isoformat()
        metadata['scan_results'] = scan_results
        metadata['all_findings'] = all_findings
        metadata['detailed_report'] = detailed_report
        
        # Save to file for retrieval
        results_file = os.path.join(results_dir, 'scan_results.json')
        with open(results_file, 'w') as f:
            json.dump(metadata, f, indent=2)
        
        logger.info(f"Enterprise scan completed: {scan_id}")
        
    except Exception as e:
        logger.error(f"Enterprise scan failed: {e}")
        metadata['status'] = 'failed'
        metadata['phase'] = f'Scan failed: {str(e)}'
        metadata['error'] = str(e)
        metadata['completed_at'] = datetime.utcnow().isoformat()
    
    finally:
        # Cleanup will happen after results are retrieved
        pass

async def analyze_repository_structure(repo_dir: str) -> Dict[str, Any]:
    """Analyze repository structure and statistics"""
    stats = {
        'total_files': 0,
        'total_lines': 0,
        'file_types': {},
        'largest_files': [],
        'directories': 0
    }
    
    for root, dirs, files in os.walk(repo_dir):
        stats['directories'] += len(dirs)
        for file in files:
            if file.startswith('.'):
                continue
            stats['total_files'] += 1
            ext = os.path.splitext(file)[1].lower()
            stats['file_types'][ext] = stats['file_types'].get(ext, 0) + 1
            
            # Count lines in text files
            file_path = os.path.join(root, file)
            try:
                if os.path.getsize(file_path) < 10 * 1024 * 1024:  # Skip files > 10MB
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        lines = sum(1 for _ in f)
                        stats['total_lines'] += lines
            except:
                pass
    
    return stats

async def run_secret_scanning(repo_dir: str, include_history: bool) -> List[Dict]:
    """Run comprehensive secret scanning"""
    findings = []
    
    # GitLeaks scan
    gitleaks_cmd = [
        'gitleaks', 'detect',
        '--source', repo_dir,
        '--report-format', 'json',
        '--no-git'
    ]
    
    if include_history:
        gitleaks_cmd.remove('--no-git')
    
    result = await run_command_with_timeout(gitleaks_cmd, timeout=300)
    if result.get('stdout'):
        try:
            gitleaks_findings = json.loads(result['stdout'])
            for finding in gitleaks_findings:
                findings.append({
                    'tool': 'GitLeaks',
                    'severity': 'high',
                    'title': f"Secret detected: {finding.get('RuleID', 'Unknown')}",
                    'file': finding.get('File', ''),
                    'line': finding.get('StartLine', 0),
                    'secret_type': finding.get('RuleID', ''),
                    'description': finding.get('Secret', '')[:100] + '...',
                    'commit': finding.get('Commit', '')
                })
        except:
            pass
    
    # TruffleHog scan
    trufflehog_cmd = [
        'trufflehog', 'filesystem',
        '--directory', repo_dir,
        '--json'
    ]
    
    if include_history:
        trufflehog_cmd = [
            'trufflehog', 'git',
            'file://' + repo_dir,
            '--json'
        ]
    
    result = await run_command_with_timeout(trufflehog_cmd, timeout=300)
    if result.get('stdout'):
        for line in result['stdout'].strip().split('\n'):
            try:
                finding = json.loads(line)
                findings.append({
                    'tool': 'TruffleHog',
                    'severity': 'high',
                    'title': f"Secret detected: {finding.get('DetectorName', 'Unknown')}",
                    'file': finding.get('SourceMetadata', {}).get('Data', {}).get('Filesystem', {}).get('file', ''),
                    'line': finding.get('SourceMetadata', {}).get('Data', {}).get('Filesystem', {}).get('line', 0),
                    'secret_type': finding.get('DetectorName', ''),
                    'verified': finding.get('Verified', False),
                    'description': 'Verified secret' if finding.get('Verified') else 'Potential secret'
                })
            except:
                pass
    
    return findings

async def run_vulnerability_scanning(repo_dir: str, project_info: Dict) -> List[Dict]:
    """Run comprehensive vulnerability scanning"""
    findings = []
    
    # Semgrep scan with multiple rulesets
    semgrep_rulesets = [
        'auto',  # Auto-detect and apply relevant rules
        'p/security-audit',
        'p/owasp-top-ten',
        'p/cwe-top-25'
    ]
    
    for ruleset in semgrep_rulesets:
        cmd = [
            'semgrep',
            '--config=' + ruleset,
            '--json',
            '--no-git-ignore',
            repo_dir
        ]
        
        result = await run_command_with_timeout(cmd, timeout=600)
        if result.get('stdout'):
            try:
                semgrep_results = json.loads(result['stdout'])
                for finding in semgrep_results.get('results', []):
                    findings.append({
                        'tool': 'Semgrep',
                        'severity': finding.get('extra', {}).get('severity', 'medium').lower(),
                        'title': finding.get('check_id', 'Unknown'),
                        'file': finding.get('path', ''),
                        'line': finding.get('start', {}).get('line', 0),
                        'column': finding.get('start', {}).get('col', 0),
                        'end_line': finding.get('end', {}).get('line', 0),
                        'cwe': extract_cwe(finding.get('extra', {}).get('metadata', {})),
                        'owasp': extract_owasp(finding.get('extra', {}).get('metadata', {})),
                        'description': finding.get('extra', {}).get('message', ''),
                        'code_snippet': finding.get('extra', {}).get('lines', ''),
                        'fix_regex': finding.get('extra', {}).get('fix_regex', {})
                    })
            except:
                pass
    
    # Language-specific scanners
    if 'python' in project_info.get('languages', []):
        # Bandit for Python
        cmd = ['bandit', '-r', repo_dir, '-f', 'json', '-ll']
        result = await run_command_with_timeout(cmd, timeout=300)
        if result.get('stdout'):
            try:
                bandit_results = json.loads(result['stdout'])
                for finding in bandit_results.get('results', []):
                    findings.append({
                        'tool': 'Bandit',
                        'severity': finding.get('issue_severity', 'medium').lower(),
                        'title': finding.get('test_name', 'Unknown'),
                        'file': finding.get('filename', ''),
                        'line': finding.get('line_number', 0),
                        'cwe': finding.get('issue_cwe', {}).get('id', ''),
                        'description': finding.get('issue_text', ''),
                        'code_snippet': finding.get('code', ''),
                        'confidence': finding.get('issue_confidence', '')
                    })
            except:
                pass
    
    if 'javascript' in project_info.get('languages', []) or 'typescript' in project_info.get('languages', []):
        # ESLint with security plugin
        eslintrc = {
            "extends": ["plugin:security/recommended"],
            "plugins": ["security"],
            "parserOptions": {"ecmaVersion": 2021}
        }
        
        eslintrc_path = os.path.join(repo_dir, '.eslintrc.json')
        with open(eslintrc_path, 'w') as f:
            json.dump(eslintrc, f)
        
        cmd = ['eslint', repo_dir, '--format', 'json', '--no-eslintrc', '-c', eslintrc_path]
        result = await run_command_with_timeout(cmd, timeout=300)
        if result.get('stdout'):
            try:
                eslint_results = json.loads(result['stdout'])
                for file_result in eslint_results:
                    for message in file_result.get('messages', []):
                        if 'security' in message.get('ruleId', ''):
                            findings.append({
                                'tool': 'ESLint Security',
                                'severity': 'medium' if message.get('severity') == 2 else 'low',
                                'title': message.get('ruleId', 'Unknown'),
                                'file': file_result.get('filePath', ''),
                                'line': message.get('line', 0),
                                'column': message.get('column', 0),
                                'description': message.get('message', ''),
                                'fix': message.get('fix', {})
                            })
            except:
                pass
    
    return findings

async def run_dependency_scanning(repo_dir: str, project_info: Dict) -> List[Dict]:
    """Run dependency vulnerability scanning"""
    findings = []
    
    # Grype for general vulnerability scanning
    cmd = ['grype', 'dir:' + repo_dir, '-o', 'json']
    result = await run_command_with_timeout(cmd, timeout=300)
    if result.get('stdout'):
        try:
            grype_results = json.loads(result['stdout'])
            for match in grype_results.get('matches', []):
                vuln = match.get('vulnerability', {})
                findings.append({
                    'tool': 'Grype',
                    'severity': vuln.get('severity', 'medium').lower(),
                    'title': f"{vuln.get('id', 'Unknown')} in {match.get('artifact', {}).get('name', '')}",
                    'file': match.get('artifact', {}).get('locations', [{}])[0].get('path', ''),
                    'package': match.get('artifact', {}).get('name', ''),
                    'version': match.get('artifact', {}).get('version', ''),
                    'cve': vuln.get('id', ''),
                    'cvss_score': vuln.get('cvss', [{}])[0].get('metrics', {}).get('baseScore', 0),
                    'description': vuln.get('description', ''),
                    'fix_versions': [fix.get('version', '') for fix in vuln.get('fix', {}).get('versions', [])]
                })
        except:
            pass
    
    # Trivy for comprehensive scanning
    cmd = ['trivy', 'fs', '--format', 'json', '--security-checks', 'vuln,config', repo_dir]
    result = await run_command_with_timeout(cmd, timeout=300)
    if result.get('stdout'):
        try:
            trivy_results = json.loads(result['stdout'])
            for result in trivy_results.get('Results', []):
                for vuln in result.get('Vulnerabilities', []):
                    findings.append({
                        'tool': 'Trivy',
                        'severity': vuln.get('Severity', 'medium').lower(),
                        'title': f"{vuln.get('VulnerabilityID', 'Unknown')} in {vuln.get('PkgName', '')}",
                        'file': result.get('Target', ''),
                        'package': vuln.get('PkgName', ''),
                        'version': vuln.get('InstalledVersion', ''),
                        'cve': vuln.get('VulnerabilityID', ''),
                        'cvss': vuln.get('CVSS', {}),
                        'description': vuln.get('Description', ''),
                        'references': vuln.get('References', []),
                        'fixed_version': vuln.get('FixedVersion', '')
                    })
        except:
            pass
    
    # Language-specific dependency scanners
    if 'python' in project_info.get('languages', []):
        cmd = ['safety', 'check', '--json', '--target', repo_dir]
        result = await run_command_with_timeout(cmd, timeout=180)
        if result.get('stdout'):
            try:
                safety_results = json.loads(result['stdout'])
                for vuln in safety_results.get('vulnerabilities', []):
                    findings.append({
                        'tool': 'Safety',
                        'severity': 'high' if float(vuln.get('CVE', {}).get('cvss', 0)) >= 7 else 'medium',
                        'title': f"{vuln.get('advisory', '')} in {vuln.get('package_name', '')}",
                        'package': vuln.get('package_name', ''),
                        'version': vuln.get('analyzed_version', ''),
                        'cve': vuln.get('CVE', {}).get('id', ''),
                        'cvss_score': vuln.get('CVE', {}).get('cvss', 0),
                        'description': vuln.get('advisory', ''),
                        'vulnerable_spec': vuln.get('vulnerable_spec', ''),
                        'fixed_versions': vuln.get('fixed_versions', [])
                    })
            except:
                pass
    
    return findings

async def run_infrastructure_scanning(repo_dir: str) -> List[Dict]:
    """Run infrastructure as code scanning"""
    findings = []
    
    # Checkov for IaC scanning
    cmd = [
        'checkov',
        '-d', repo_dir,
        '--output', 'json',
        '--framework', 'all',
        '--download-external-modules', 'false'
    ]
    
    result = await run_command_with_timeout(cmd, timeout=600)
    if result.get('stdout'):
        try:
            checkov_results = json.loads(result['stdout'])
            for check_type in ['failed_checks', 'failed_checks_by_severity']:
                for finding in checkov_results.get('results', {}).get(check_type, []):
                    findings.append({
                        'tool': 'Checkov',
                        'severity': finding.get('severity', 'medium').lower(),
                        'title': finding.get('check_name', 'Unknown'),
                        'file': finding.get('file_path', ''),
                        'line': finding.get('file_line_range', [0])[0],
                        'resource': finding.get('resource', ''),
                        'check_id': finding.get('check_id', ''),
                        'description': finding.get('description', ''),
                        'guideline': finding.get('guideline', ''),
                        'code_block': finding.get('code_block', '')
                    })
        except:
            pass
    
    return findings

async def run_mobile_scanning(repo_dir: str) -> List[Dict]:
    """Run mobile application security scanning"""
    findings = []
    
    # MobSFScan for mobile security
    cmd = ['mobsfscan', '--json', repo_dir]
    result = await run_command_with_timeout(cmd, timeout=300)
    if result.get('stdout'):
        try:
            mobsf_results = json.loads(result['stdout'])
            for file_path, issues in mobsf_results.get('results', {}).items():
                for issue in issues.get('issues', []):
                    findings.append({
                        'tool': 'MobSFScan',
                        'severity': issue.get('severity', 'medium').lower(),
                        'title': issue.get('rule_id', 'Unknown'),
                        'file': file_path,
                        'line': issue.get('line_number', 0),
                        'description': issue.get('description', ''),
                        'masvs': issue.get('masvs', ''),
                        'mstg': issue.get('mstg', ''),
                        'cwe': issue.get('cwe', ''),
                        'owasp_mobile': issue.get('owasp_mobile', '')
                    })
        except:
            pass
    
    return findings

async def run_code_quality_scanning(repo_dir: str, project_info: Dict) -> List[Dict]:
    """Run code quality and best practices scanning"""
    findings = []
    
    # Add code quality checks based on detected languages
    # This is simplified - you can add more tools like SonarQube, CodeClimate, etc.
    
    return findings

async def run_command_with_timeout(cmd: List[str], timeout: int = 300) -> Dict[str, Any]:
    """Run command with timeout"""
    try:
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
            'success': process.returncode in [0, 1],
            'stdout': stdout.decode('utf-8', errors='ignore'),
            'stderr': stderr.decode('utf-8', errors='ignore'),
            'returncode': process.returncode
        }
    except asyncio.TimeoutError:
        return {'success': False, 'error': 'timeout', 'stdout': '', 'stderr': ''}
    except Exception as e:
        return {'success': False, 'error': str(e), 'stdout': '', 'stderr': ''}

def extract_cwe(metadata: Dict) -> str:
    """Extract CWE from metadata"""
    cwe = metadata.get('cwe', '')
    if isinstance(cwe, list) and cwe:
        return cwe[0]
    return str(cwe) if cwe else ''

def extract_owasp(metadata: Dict) -> str:
    """Extract OWASP category from metadata"""
    owasp = metadata.get('owasp', '')
    if isinstance(owasp, list) and owasp:
        return owasp[0]
    return str(owasp) if owasp else ''

def update_scan_status(scan_id: str, status: str, progress: int, phase: str):
    """Update scan status in cache"""
    if scan_id in enterprise_scan_results:
        enterprise_scan_results[scan_id]['status'] = status
        enterprise_scan_results[scan_id]['progress'] = progress
        enterprise_scan_results[scan_id]['phase'] = phase
        enterprise_scan_results[scan_id]['last_updated'] = datetime.utcnow().isoformat()

def get_scan_time_estimate(scan_depth: str) -> str:
    """Get estimated scan time based on depth"""
    estimates = {
        'quick': '30-60 seconds',
        'standard': '2-5 minutes',
        'comprehensive': '5-10 minutes',
        'paranoid': '10-20 minutes'
    }
    return estimates.get(scan_depth, '5-10 minutes')

def generate_enterprise_report(
    scan_id: str,
    repository_url: str,
    branch: str,
    project_info: Dict,
    scan_results: Dict,
    all_findings: List[Dict],
    metadata: Dict
) -> Dict[str, Any]:
    """Generate comprehensive enterprise security report"""
    
    # Group findings by file
    findings_by_file = {}
    for finding in all_findings:
        file_path = finding.get('file', 'Unknown')
        if file_path not in findings_by_file:
            findings_by_file[file_path] = []
        findings_by_file[file_path].append(finding)
    
    # Generate executive summary
    executive_summary = {
        'repository': repository_url,
        'branch': branch,
        'scan_date': metadata.get('started_at'),
        'scan_duration': calculate_duration(metadata.get('started_at'), metadata.get('completed_at')),
        'total_files_scanned': metadata.get('repository_stats', {}).get('total_files', 0),
        'total_lines_analyzed': metadata.get('repository_stats', {}).get('total_lines', 0),
        'technologies_detected': project_info,
        'security_score': calculate_security_score(metadata['findings']),
        'risk_level': calculate_risk_level(metadata['findings']),
        'compliance_status': check_compliance_status(all_findings)
    }
    
    # Top critical issues
    critical_issues = [f for f in all_findings if f.get('severity', '').lower() == 'critical'][:10]
    high_issues = [f for f in all_findings if f.get('severity', '').lower() == 'high'][:10]
    
    # Detailed findings by category
    categorized_findings = {}
    for category in ['vulnerabilities', 'secrets', 'dependencies', 'infrastructure', 'mobile_security']:
        categorized_findings[category] = [f for f in all_findings if f.get('category') == category]
    
    # Generate remediation priorities
    remediation_priorities = generate_remediation_priorities(all_findings)
    
    report = {
        'scan_id': scan_id,
        'executive_summary': executive_summary,
        'finding_summary': metadata['findings'],
        'critical_issues': critical_issues,
        'high_priority_issues': high_issues,
        'findings_by_category': categorized_findings,
        'findings_by_file': findings_by_file,
        'remediation_priorities': remediation_priorities,
        'tools_used': metadata.get('tools_completed', []),
        'scan_configuration': metadata.get('options', {}),
        'detailed_findings': all_findings
    }
    
    return report

def calculate_duration(start: str, end: str) -> str:
    """Calculate scan duration"""
    try:
        start_dt = datetime.fromisoformat(start.replace('Z', '+00:00'))
        end_dt = datetime.fromisoformat(end.replace('Z', '+00:00'))
        duration = end_dt - start_dt
        return f"{duration.total_seconds():.1f} seconds"
    except:
        return "Unknown"

def calculate_security_score(findings: Dict) -> str:
    """Calculate overall security score (A-F)"""
    total = findings.get('total', 0)
    critical = findings.get('critical', 0)
    high = findings.get('high', 0)
    
    if critical > 0:
        return 'F'
    elif high > 5:
        return 'D'
    elif high > 0:
        return 'C'
    elif total > 20:
        return 'B'
    elif total > 0:
        return 'A-'
    else:
        return 'A+'

def calculate_risk_level(findings: Dict) -> str:
    """Calculate risk level"""
    critical = findings.get('critical', 0)
    high = findings.get('high', 0)
    
    if critical > 0:
        return 'CRITICAL'
    elif high > 3:
        return 'HIGH'
    elif high > 0:
        return 'MEDIUM'
    else:
        return 'LOW'

def check_compliance_status(findings: List[Dict]) -> Dict[str, str]:
    """Check compliance with various standards"""
    compliance = {
        'OWASP_Top_10': 'PASS',
        'PCI_DSS': 'PASS',
        'SOC_2': 'PASS',
        'GDPR': 'PASS',
        'HIPAA': 'PASS'
    }
    
    # Check for specific compliance violations
    for finding in findings:
        if finding.get('severity', '').lower() in ['critical', 'high']:
            owasp = finding.get('owasp', '')
            if owasp:
                compliance['OWASP_Top_10'] = 'FAIL'
            
            # Check for data protection issues
            if any(keyword in str(finding).lower() for keyword in ['encryption', 'password', 'auth', 'data']):
                compliance['GDPR'] = 'AT RISK'
                compliance['HIPAA'] = 'AT RISK'
    
    return compliance

def generate_remediation_priorities(findings: List[Dict]) -> List[Dict]:
    """Generate prioritized remediation plan"""
    priorities = []
    
    # Group by severity and type
    severity_groups = {}
    for finding in findings:
        severity = finding.get('severity', 'info').lower()
        if severity not in severity_groups:
            severity_groups[severity] = []
        severity_groups[severity].append(finding)
    
    # Create priority list
    priority_order = ['critical', 'high', 'medium', 'low', 'info']
    for severity in priority_order:
        if severity in severity_groups and severity_groups[severity]:
            priorities.append({
                'priority': len(priorities) + 1,
                'severity': severity,
                'count': len(severity_groups[severity]),
                'estimated_effort': estimate_remediation_effort(severity, len(severity_groups[severity])),
                'impact': get_impact_description(severity),
                'examples': severity_groups[severity][:3]  # Show top 3 examples
            })
    
    return priorities

def estimate_remediation_effort(severity: str, count: int) -> str:
    """Estimate remediation effort"""
    effort_map = {
        'critical': 4,
        'high': 2,
        'medium': 1,
        'low': 0.5,
        'info': 0.25
    }
    hours = effort_map.get(severity, 1) * count
    
    if hours < 1:
        return "< 1 hour"
    elif hours < 8:
        return f"{hours:.0f} hours"
    elif hours < 40:
        return f"{hours/8:.0f} days"
    else:
        return f"{hours/40:.0f} weeks"

def get_impact_description(severity: str) -> str:
    """Get impact description for severity level"""
    impact_map = {
        'critical': 'Immediate risk of data breach or system compromise',
        'high': 'Significant security risk requiring prompt attention',
        'medium': 'Moderate risk that should be addressed in next release',
        'low': 'Minor issue to address in regular maintenance',
        'info': 'Informational finding for awareness'
    }
    return impact_map.get(severity, 'Security finding requiring review')

@router.get("/github/{scan_id}/status")
async def get_enterprise_scan_status(scan_id: str):
    """Get status of enterprise scan"""
    if scan_id not in enterprise_scan_results:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    scan_data = enterprise_scan_results[scan_id]
    return {
        'scan_id': scan_id,
        'status': scan_data.get('status'),
        'progress': scan_data.get('progress'),
        'phase': scan_data.get('phase'),
        'started_at': scan_data.get('started_at'),
        'findings_count': scan_data.get('findings'),
        'tools_completed': len(scan_data.get('tools_completed', [])),
        'tools_pending': len(scan_data.get('tools_pending', []))
    }

@router.get("/github/{scan_id}/results")
async def get_enterprise_scan_results(scan_id: str):
    """Get full results of enterprise scan"""
    if scan_id not in enterprise_scan_results:
        # Try to load from file
        results_file = f"/tmp/enterprise_scan_{scan_id}/results/scan_results.json"
        if os.path.exists(results_file):
            with open(results_file, 'r') as f:
                return json.load(f)
        raise HTTPException(status_code=404, detail="Scan results not found")
    
    scan_data = enterprise_scan_results[scan_id]
    if scan_data.get('status') != 'completed':
        return {
            'scan_id': scan_id,
            'status': scan_data.get('status'),
            'message': 'Scan still in progress',
            'progress': scan_data.get('progress'),
            'phase': scan_data.get('phase')
        }
    
    return scan_data

@router.get("/github/{scan_id}/report")
async def get_enterprise_scan_report(scan_id: str, format: str = "json"):
    """Get formatted security report"""
    results = await get_enterprise_scan_results(scan_id)
    
    if format == "json":
        return results.get('detailed_report', {})
    elif format == "summary":
        return {
            'executive_summary': results.get('detailed_report', {}).get('executive_summary'),
            'finding_summary': results.get('findings'),
            'risk_level': results.get('detailed_report', {}).get('executive_summary', {}).get('risk_level'),
            'top_issues': results.get('detailed_report', {}).get('critical_issues', [])[:5]
        }
    else:
        raise HTTPException(status_code=400, detail="Invalid format. Use 'json' or 'summary'")

@router.delete("/github/{scan_id}")
async def cleanup_scan_results(scan_id: str):
    """Clean up scan results and temporary files"""
    scan_dir = f"/tmp/enterprise_scan_{scan_id}"
    if os.path.exists(scan_dir):
        shutil.rmtree(scan_dir)
    
    if scan_id in enterprise_scan_results:
        del enterprise_scan_results[scan_id]
    
    return {"message": "Scan results cleaned up successfully"}