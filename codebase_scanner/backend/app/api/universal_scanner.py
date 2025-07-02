"""
Universal file upload scanner with multi-language support and AI analysis
"""
import os
import uuid
import tempfile
import zipfile
import tarfile
import subprocess
import json
import asyncio
from datetime import datetime
from typing import Dict, Any, List, Optional, Tuple
from pathlib import Path
from fastapi import APIRouter, HTTPException, UploadFile, File, Form, BackgroundTasks
from fastapi.responses import JSONResponse
import aiofiles
import anthropic

router = APIRouter(prefix="/scans", tags=["universal"])

# Language detection patterns
LANGUAGE_EXTENSIONS = {
    '.py': 'python',
    '.js': 'javascript',
    '.jsx': 'javascript',
    '.ts': 'typescript',
    '.tsx': 'typescript',
    '.java': 'java',
    '.cpp': 'cpp',
    '.cc': 'cpp',
    '.cxx': 'cpp',
    '.c': 'c',
    '.h': 'c',
    '.hpp': 'cpp',
    '.cs': 'csharp',
    '.rb': 'ruby',
    '.go': 'go',
    '.rs': 'rust',
    '.php': 'php',
    '.swift': 'swift',
    '.kt': 'kotlin',
    '.scala': 'scala',
    '.r': 'r',
    '.m': 'objective-c',
    '.mm': 'objective-c',
    '.pl': 'perl',
    '.sh': 'bash',
    '.lua': 'lua',
    '.dart': 'dart',
    '.sol': 'solidity',
    '.vy': 'vyper',
    '.yml': 'yaml',
    '.yaml': 'yaml',
    '.json': 'json',
    '.xml': 'xml',
    '.sql': 'sql',
    '.tf': 'terraform',
    '.dockerfile': 'docker',
    'Dockerfile': 'docker',
}

# Security scanners for each language
LANGUAGE_SCANNERS = {
    'python': ['bandit', 'safety', 'semgrep'],
    'javascript': ['semgrep', 'retire', 'eslint-security'],
    'typescript': ['semgrep', 'retire', 'eslint-security'],
    'java': ['semgrep', 'spotbugs', 'dependency-check'],
    'go': ['gosec', 'semgrep'],
    'ruby': ['brakeman', 'bundler-audit', 'semgrep'],
    'php': ['phpcs-security-audit', 'semgrep'],
    'c': ['flawfinder', 'cppcheck', 'semgrep'],
    'cpp': ['flawfinder', 'cppcheck', 'semgrep'],
    'csharp': ['security-code-scan', 'semgrep'],
    'rust': ['cargo-audit', 'semgrep'],
    'swift': ['swiftlint', 'semgrep'],
    'kotlin': ['detekt', 'semgrep'],
    'default': ['semgrep', 'gitleaks', 'trufflehog']
}

class UniversalScanner:
    """Universal scanner for any programming language"""
    
    def __init__(self):
        self.anthropic_client = None
        if os.getenv("ANTHROPIC_API_KEY"):
            self.anthropic_client = anthropic.Anthropic(
                api_key=os.getenv("ANTHROPIC_API_KEY")
            )
    
    async def detect_languages(self, directory: str) -> Dict[str, int]:
        """Detect programming languages in the uploaded files"""
        language_counts = {}
        
        for root, _, files in os.walk(directory):
            for file in files:
                ext = Path(file).suffix.lower()
                if ext in LANGUAGE_EXTENSIONS:
                    lang = LANGUAGE_EXTENSIONS[ext]
                    language_counts[lang] = language_counts.get(lang, 0) + 1
                elif file.lower() == 'dockerfile':
                    language_counts['docker'] = language_counts.get('docker', 0) + 1
        
        return language_counts
    
    async def scan_with_semgrep(self, directory: str) -> Dict[str, Any]:
        """Run Semgrep for multi-language scanning"""
        try:
            cmd = ["semgrep", "--config=auto", "--json", directory]
            result = await self._run_command(cmd, timeout=300)
            
            if result['success'] and result['stdout']:
                findings = json.loads(result['stdout'])
                return {
                    'success': True,
                    'findings': self._parse_semgrep_findings(findings)
                }
        except Exception as e:
            print(f"Semgrep scan error: {e}")
        
        return {'success': False, 'findings': []}
    
    async def scan_for_secrets(self, directory: str) -> Dict[str, Any]:
        """Scan for hardcoded secrets and credentials"""
        all_secrets = []
        
        # Run multiple secret scanners
        scanners = [
            ("gitleaks", ["gitleaks", "detect", "--source", directory, "--report-format", "json"]),
            ("trufflehog", ["trufflehog", "filesystem", directory, "--json"]),
            ("detect-secrets", ["detect-secrets", "scan", directory])
        ]
        
        for scanner_name, cmd in scanners:
            try:
                result = await self._run_command(cmd, timeout=120)
                if result['success'] and result['stdout']:
                    secrets = self._parse_secret_findings(scanner_name, result['stdout'])
                    all_secrets.extend(secrets)
            except Exception as e:
                print(f"{scanner_name} error: {e}")
        
        return {
            'success': True,
            'secrets_found': len(all_secrets),
            'findings': all_secrets
        }
    
    async def scan_language_specific(self, directory: str, language: str) -> List[Dict]:
        """Run language-specific security scanners"""
        findings = []
        scanners = LANGUAGE_SCANNERS.get(language, LANGUAGE_SCANNERS['default'])
        
        for scanner in scanners:
            if scanner == 'bandit' and language == 'python':
                result = await self._run_bandit(directory)
                findings.extend(result.get('findings', []))
            
            elif scanner == 'gosec' and language == 'go':
                result = await self._run_gosec(directory)
                findings.extend(result.get('findings', []))
            
            elif scanner == 'brakeman' and language == 'ruby':
                result = await self._run_brakeman(directory)
                findings.extend(result.get('findings', []))
            
            # Add more language-specific scanners as needed
        
        return findings
    
    async def analyze_with_claude(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """Use Claude AI to analyze findings and provide remediation recommendations"""
        if not self.anthropic_client:
            return {
                'success': False,
                'error': 'Claude API not configured. Set ANTHROPIC_API_KEY environment variable.'
            }
        
        try:
            # Prepare context for Claude
            context = self._prepare_claude_context(scan_results)
            
            # Get Claude's analysis
            message = self.anthropic_client.messages.create(
                model="claude-3-5-sonnet-20241022",
                max_tokens=4000,
                temperature=0,
                messages=[{
                    "role": "user",
                    "content": f"""You are a senior security engineer analyzing code vulnerabilities. 
                    
{context}

Please provide:
1. Executive Summary - Brief overview of security posture
2. Critical Issues - Top 3-5 most dangerous vulnerabilities
3. Detailed Analysis - For each vulnerability:
   - Description of the issue
   - Potential impact
   - CVSS score estimate
   - Exploitation difficulty
4. Remediation Plan - Specific fixes for each issue with code examples
5. Security Best Practices - General recommendations for this codebase
6. Implementation Priority - Ordered list of fixes by risk/effort

Format your response in clear sections with markdown."""
                }]
            )
            
            return {
                'success': True,
                'analysis': message.content[0].text,
                'tokens_used': message.usage.total_tokens
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': f'Claude analysis failed: {str(e)}'
            }
    
    async def _run_command(self, cmd: List[str], timeout: int = 60) -> Dict[str, Any]:
        """Run a command asynchronously"""
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
                'success': process.returncode == 0,
                'stdout': stdout.decode('utf-8', errors='ignore'),
                'stderr': stderr.decode('utf-8', errors='ignore')
            }
        except asyncio.TimeoutError:
            return {'success': False, 'error': 'Command timed out'}
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    async def _run_bandit(self, directory: str) -> Dict[str, Any]:
        """Run Bandit for Python security scanning"""
        cmd = ["bandit", "-r", directory, "-f", "json"]
        result = await self._run_command(cmd)
        
        if result['success'] and result['stdout']:
            try:
                data = json.loads(result['stdout'])
                findings = []
                for issue in data.get('results', []):
                    findings.append({
                        'tool': 'bandit',
                        'language': 'python',
                        'severity': issue['issue_severity'],
                        'confidence': issue['issue_confidence'],
                        'title': issue['issue_text'],
                        'file': issue['filename'],
                        'line': issue['line_number'],
                        'code': issue.get('code', ''),
                        'cwe': issue.get('issue_cwe', {}).get('id', '')
                    })
                return {'success': True, 'findings': findings}
            except Exception as e:
                print(f"Bandit parsing error: {e}")
        
        return {'success': False, 'findings': []}
    
    async def _run_gosec(self, directory: str) -> Dict[str, Any]:
        """Run gosec for Go security scanning"""
        cmd = ["gosec", "-fmt", "json", directory]
        result = await self._run_command(cmd)
        
        if result['success'] and result['stdout']:
            try:
                data = json.loads(result['stdout'])
                findings = []
                for issue in data.get('Issues', []):
                    findings.append({
                        'tool': 'gosec',
                        'language': 'go',
                        'severity': issue['severity'],
                        'confidence': issue['confidence'],
                        'title': issue['details'],
                        'file': issue['file'],
                        'line': issue['line'],
                        'code': issue.get('code', ''),
                        'cwe': issue.get('cwe', {}).get('ID', '')
                    })
                return {'success': True, 'findings': findings}
            except Exception as e:
                print(f"Gosec parsing error: {e}")
        
        return {'success': False, 'findings': []}
    
    async def _run_brakeman(self, directory: str) -> Dict[str, Any]:
        """Run Brakeman for Ruby on Rails security scanning"""
        cmd = ["brakeman", "-f", "json", "-q", directory]
        result = await self._run_command(cmd)
        
        if result['success'] and result['stdout']:
            try:
                data = json.loads(result['stdout'])
                findings = []
                for warning in data.get('warnings', []):
                    findings.append({
                        'tool': 'brakeman',
                        'language': 'ruby',
                        'severity': warning['confidence'],
                        'title': warning['message'],
                        'file': warning['file'],
                        'line': warning['line'],
                        'code': warning.get('code', ''),
                        'check_name': warning.get('check_name', '')
                    })
                return {'success': True, 'findings': findings}
            except Exception as e:
                print(f"Brakeman parsing error: {e}")
        
        return {'success': False, 'findings': []}
    
    def _parse_semgrep_findings(self, data: Dict) -> List[Dict]:
        """Parse Semgrep JSON output"""
        findings = []
        for result in data.get('results', []):
            findings.append({
                'tool': 'semgrep',
                'severity': result.get('extra', {}).get('severity', 'medium'),
                'title': result.get('check_id', ''),
                'message': result.get('extra', {}).get('message', ''),
                'file': result.get('path', ''),
                'line': result.get('start', {}).get('line', 0),
                'code': result.get('extra', {}).get('lines', ''),
                'fix': result.get('extra', {}).get('fix', ''),
                'cwe': result.get('extra', {}).get('metadata', {}).get('cwe', [])
            })
        return findings
    
    def _parse_secret_findings(self, scanner: str, output: str) -> List[Dict]:
        """Parse secret scanner outputs"""
        findings = []
        
        try:
            if scanner == 'gitleaks':
                data = json.loads(output) if output else []
                for finding in data:
                    findings.append({
                        'tool': 'gitleaks',
                        'type': 'secret',
                        'severity': 'high',
                        'title': f"Potential secret: {finding.get('RuleID', 'Unknown')}",
                        'file': finding.get('File', ''),
                        'line': finding.get('StartLine', 0),
                        'secret_type': finding.get('RuleID', ''),
                        'match': finding.get('Match', '')[:50] + '...' if finding.get('Match') else ''
                    })
            
            elif scanner == 'trufflehog':
                # Parse TruffleHog JSON output line by line
                for line in output.strip().split('\n'):
                    if line:
                        try:
                            finding = json.loads(line)
                            findings.append({
                                'tool': 'trufflehog',
                                'type': 'secret',
                                'severity': 'high',
                                'title': f"Secret found: {finding.get('DetectorName', 'Unknown')}",
                                'file': finding.get('SourceMetadata', {}).get('Data', {}).get('Filesystem', {}).get('file', ''),
                                'verified': finding.get('Verified', False)
                            })
                        except:
                            pass
        except Exception as e:
            print(f"Secret parser error for {scanner}: {e}")
        
        return findings
    
    def _prepare_claude_context(self, scan_results: Dict) -> str:
        """Prepare context for Claude analysis"""
        context = f"""Code Security Analysis Results:

Languages Detected: {', '.join(scan_results.get('languages', {}).keys())}
Total Files Scanned: {scan_results.get('files_scanned', 0)}
Total Security Findings: {scan_results.get('total_findings', 0)}
Secrets Found: {scan_results.get('secrets', {}).get('secrets_found', 0)}

Detailed Findings:
"""
        
        # Add top findings
        findings = scan_results.get('findings', [])[:20]  # Limit to top 20
        for i, finding in enumerate(findings, 1):
            context += f"\n{i}. [{finding.get('severity', 'unknown').upper()}] {finding.get('title', 'Unknown issue')}"
            context += f"\n   File: {finding.get('file', 'unknown')}"
            context += f"\n   Line: {finding.get('line', 'unknown')}"
            if finding.get('code'):
                context += f"\n   Code: {finding.get('code', '')[:100]}..."
            context += "\n"
        
        return context

@router.post("/upload-universal")
async def scan_uploaded_file(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    enable_ai_analysis: bool = Form(True),
    scan_type: str = Form("comprehensive")
):
    """
    Universal file upload scanner for any programming language
    
    Supports:
    - Single files or archives (zip, tar, tar.gz)
    - 30+ programming languages
    - AI-powered vulnerability analysis
    - Detailed remediation recommendations
    """
    
    # Validate file
    if not file.filename:
        raise HTTPException(status_code=400, detail="No file provided")
    
    # Check file size (max 100MB)
    file_size = 0
    contents = await file.read()
    file_size = len(contents)
    await file.seek(0)
    
    if file_size > 100 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="File too large. Maximum size is 100MB")
    
    # Generate scan ID
    scan_id = str(uuid.uuid4())
    
    # Save uploaded file to a persistent location
    scan_dir = f"/tmp/scan_{scan_id}"
    os.makedirs(scan_dir, exist_ok=True)
    
    file_path = os.path.join(scan_dir, file.filename)
    
    async with aiofiles.open(file_path, 'wb') as f:
        await f.write(contents)
    
    # Extract if archive
    extract_dir = os.path.join(scan_dir, "extracted")
    os.makedirs(extract_dir, exist_ok=True)
    
    if file.filename.endswith(('.zip', '.tar', '.tar.gz', '.tgz')):
        try:
            if file.filename.endswith('.zip'):
                with zipfile.ZipFile(file_path, 'r') as zip_ref:
                    zip_ref.extractall(extract_dir)
            else:
                with tarfile.open(file_path, 'r:*') as tar_ref:
                    tar_ref.extractall(extract_dir)
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Failed to extract archive: {str(e)}")
    else:
        # Copy single file
        import shutil
        shutil.copy2(file_path, os.path.join(extract_dir, file.filename))
    
    # Start background scan
    background_tasks.add_task(
        run_universal_scan,
        scan_id=scan_id,
        directory=extract_dir,
        filename=file.filename,
        enable_ai_analysis=enable_ai_analysis
    )
    
    return {
        "scan_id": scan_id,
        "status": "initiated",
        "message": "Scan started successfully",
        "filename": file.filename,
        "file_size": file_size,
        "enable_ai_analysis": enable_ai_analysis
    }

async def run_universal_scan(
    scan_id: str,
    directory: str,
    filename: str,
    enable_ai_analysis: bool
):
    """Run the universal security scan"""
    scanner = UniversalScanner()
    results = {
        "scan_id": scan_id,
        "filename": filename,
        "status": "running",
        "started_at": datetime.utcnow().isoformat(),
        "languages": {},
        "findings": [],
        "secrets": {},
        "ai_analysis": None
    }
    
    try:
        print(f"\n🔍 Starting universal scan for: {filename}")
        
        # Detect languages
        print("📝 Detecting programming languages...")
        results['languages'] = await scanner.detect_languages(directory)
        print(f"   Languages found: {', '.join(results['languages'].keys())}")
        
        # Count files
        file_count = sum(1 for _, _, files in os.walk(directory) for f in files)
        results['files_scanned'] = file_count
        
        # Run Semgrep (multi-language)
        print("🔧 Running Semgrep multi-language scan...")
        semgrep_results = await scanner.scan_with_semgrep(directory)
        if semgrep_results['success']:
            results['findings'].extend(semgrep_results['findings'])
        
        # Scan for secrets
        print("🔐 Scanning for hardcoded secrets...")
        secret_results = await scanner.scan_for_secrets(directory)
        results['secrets'] = secret_results
        if secret_results['findings']:
            results['findings'].extend(secret_results['findings'])
        
        # Run language-specific scanners
        for language in results['languages'].keys():
            print(f"🔧 Running {language}-specific security scanners...")
            lang_findings = await scanner.scan_language_specific(directory, language)
            results['findings'].extend(lang_findings)
        
        # Calculate summary
        results['total_findings'] = len(results['findings'])
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        for finding in results['findings']:
            severity = finding.get('severity', 'medium').lower()
            if severity in severity_counts:
                severity_counts[severity] += 1
        results['severity_counts'] = severity_counts
        
        # AI Analysis
        if enable_ai_analysis and results['findings']:
            print("🤖 Running Claude AI analysis...")
            ai_results = await scanner.analyze_with_claude(results)
            results['ai_analysis'] = ai_results
        
        results['status'] = 'completed'
        results['completed_at'] = datetime.utcnow().isoformat()
        
        print(f"✅ Scan completed! Total findings: {results['total_findings']}")
        
    except Exception as e:
        results['status'] = 'failed'
        results['error'] = str(e)
        print(f"❌ Scan failed: {e}")
    
    # Save results
    save_scan_results(scan_id, results)
    
    # Cleanup scan directory
    try:
        scan_dir = f"/tmp/scan_{scan_id}"
        if os.path.exists(scan_dir):
            import shutil
            shutil.rmtree(scan_dir)
            print(f"🧹 Cleaned up scan directory: {scan_dir}")
    except Exception as e:
        print(f"⚠️  Failed to cleanup scan directory: {e}")

def save_scan_results(scan_id: str, results: Dict[str, Any]):
    """Save scan results to file"""
    output_file = f"/tmp/universal_scan_{scan_id}.json"
    try:
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"💾 Results saved to: {output_file}")
    except Exception as e:
        print(f"⚠️  Failed to save results: {e}")

@router.get("/upload-universal/{scan_id}/status")
async def get_scan_status(scan_id: str):
    """Get the status of a universal scan"""
    results_file = f"/tmp/universal_scan_{scan_id}.json"
    
    if os.path.exists(results_file):
        with open(results_file, 'r') as f:
            results = json.load(f)
        return {
            "scan_id": scan_id,
            "status": results.get("status", "unknown"),
            "filename": results.get("filename", ""),
            "languages": list(results.get("languages", {}).keys()),
            "total_findings": results.get("total_findings", 0),
            "has_ai_analysis": bool(results.get("ai_analysis", {}).get("success", False))
        }
    else:
        raise HTTPException(status_code=404, detail="Scan not found")

@router.get("/upload-universal/{scan_id}/results")
async def get_scan_results(scan_id: str):
    """Get the full results of a universal scan"""
    results_file = f"/tmp/universal_scan_{scan_id}.json"
    
    if os.path.exists(results_file):
        with open(results_file, 'r') as f:
            return json.load(f)
    else:
        raise HTTPException(status_code=404, detail="Scan results not found")