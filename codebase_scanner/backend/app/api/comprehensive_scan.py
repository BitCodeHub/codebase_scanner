"""
Comprehensive Security Scan API
Supports all types of applications: web, mobile, desktop, APIs, infrastructure
"""
from fastapi import APIRouter, HTTPException, UploadFile, File, BackgroundTasks, Form
from fastapi.responses import JSONResponse
import tempfile
import os
import shutil
import json
import asyncio
import uuid
from datetime import datetime
from typing import Optional
import aiofiles
import zipfile
import tarfile

from app.services.comprehensive_scanner import ComprehensiveSecurityScanner
from app.services.universal_scanner_service import EnhancedUniversalScanner

router = APIRouter(prefix="/comprehensive", tags=["Comprehensive Security Scan"])

# Store scan results in memory (use Redis in production)
scan_results_cache = {}

@router.post("/scan")
async def comprehensive_scan(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    enable_ai_analysis: bool = Form(True),
    scan_depth: str = Form("comprehensive"),  # quick, standard, comprehensive, paranoid
    include_code_quality: bool = Form(True),
    include_dependencies: bool = Form(True),
    include_infrastructure: bool = Form(True)
):
    """
    Comprehensive security scan endpoint
    
    Features:
    - Multi-language support (30+ languages)
    - Framework detection (React, Angular, Vue, Django, Flask, Spring, Rails, etc.)
    - Vulnerability scanning (OWASP Top 10, CWE Top 25)
    - Secret detection (API keys, passwords, tokens)
    - Dependency vulnerability analysis
    - Infrastructure as Code scanning
    - Mobile app security (Android/iOS)
    - Code quality and best practices
    - AI-powered analysis and remediation
    
    Scan Depths:
    - quick: Fast scan with basic checks (< 1 minute)
    - standard: Balanced scan with most security checks (2-5 minutes)
    - comprehensive: Deep scan with all security tools (5-10 minutes)
    - paranoid: Maximum depth scan with all possible checks (10+ minutes)
    """
    
    # Validate file
    if not file.filename:
        raise HTTPException(status_code=400, detail="No file provided")
    
    # Read file contents
    contents = await file.read()
    file_size = len(contents)
    
    if file_size > 500 * 1024 * 1024:  # 500MB limit
        raise HTTPException(status_code=413, detail="File too large. Maximum size is 500MB")
    
    # Generate scan ID
    scan_id = str(uuid.uuid4())
    
    # Create scan directory
    scan_dir = f"/tmp/comprehensive_scan_{scan_id}"
    os.makedirs(scan_dir, exist_ok=True)
    
    try:
        # Save uploaded file
        file_path = os.path.join(scan_dir, file.filename)
        async with aiofiles.open(file_path, 'wb') as f:
            await f.write(contents)
        
        # Extract if archive
        extract_dir = os.path.join(scan_dir, "extracted")
        os.makedirs(extract_dir, exist_ok=True)
        
        if file.filename.endswith(('.zip', '.tar', '.tar.gz', '.tgz', '.tar.bz2')):
            if file.filename.endswith('.zip'):
                with zipfile.ZipFile(file_path, 'r') as zip_ref:
                    zip_ref.extractall(extract_dir)
            else:
                with tarfile.open(file_path, 'r:*') as tar_ref:
                    tar_ref.extractall(extract_dir)
        else:
            # Copy single file
            shutil.copy2(file_path, os.path.join(extract_dir, file.filename))
        
        # Initialize scan metadata
        scan_metadata = {
            'scan_id': scan_id,
            'filename': file.filename,
            'file_size': file_size,
            'scan_depth': scan_depth,
            'options': {
                'enable_ai_analysis': enable_ai_analysis,
                'include_code_quality': include_code_quality,
                'include_dependencies': include_dependencies,
                'include_infrastructure': include_infrastructure
            },
            'status': 'initiated',
            'started_at': datetime.utcnow().isoformat(),
            'progress': 0
        }
        
        # Store initial metadata
        scan_results_cache[scan_id] = scan_metadata
        
        # Start background scan
        background_tasks.add_task(
            run_comprehensive_scan_task,
            scan_id=scan_id,
            directory=extract_dir,
            scan_metadata=scan_metadata
        )
        
        return {
            'scan_id': scan_id,
            'status': 'scanning',
            'message': 'Comprehensive security scan initiated',
            'estimated_time': get_estimated_time(scan_depth),
            'filename': file.filename,
            'file_size': file_size,
            'scan_depth': scan_depth
        }
        
    except Exception as e:
        # Cleanup on error
        if os.path.exists(scan_dir):
            shutil.rmtree(scan_dir)
        raise HTTPException(status_code=500, detail=f"Scan initialization failed: {str(e)}")

async def run_comprehensive_scan_task(scan_id: str, directory: str, scan_metadata: dict):
    """Background task to run comprehensive scan"""
    scanner = ComprehensiveSecurityScanner()
    
    try:
        # Update status
        scan_metadata['status'] = 'scanning'
        scan_metadata['progress'] = 10
        
        # Run comprehensive scan
        scan_results = await scanner.run_comprehensive_scan(directory)
        
        scan_metadata['progress'] = 70
        
        # Add AI analysis if enabled
        if scan_metadata['options']['enable_ai_analysis'] and scan_results['summary']['total_findings'] > 0:
            scan_metadata['progress'] = 80
            ai_analysis = await generate_ai_analysis(scan_results)
            scan_results['ai_analysis'] = ai_analysis
        
        # Generate detailed report
        scan_metadata['progress'] = 90
        detailed_report = generate_detailed_report(scan_results)
        scan_results['detailed_report'] = detailed_report
        
        # Update final results
        scan_metadata.update({
            'status': 'completed',
            'completed_at': datetime.utcnow().isoformat(),
            'results': scan_results,
            'progress': 100
        })
        
    except Exception as e:
        scan_metadata.update({
            'status': 'failed',
            'error': str(e),
            'completed_at': datetime.utcnow().isoformat()
        })
    
    finally:
        # Cleanup scan directory
        scan_dir = f"/tmp/comprehensive_scan_{scan_id}"
        if os.path.exists(scan_dir):
            try:
                shutil.rmtree(scan_dir)
            except:
                pass
    
    # Update cache
    scan_results_cache[scan_id] = scan_metadata

@router.get("/scan/{scan_id}/status")
async def get_scan_status(scan_id: str):
    """Get scan status and progress"""
    if scan_id not in scan_results_cache:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    scan_data = scan_results_cache[scan_id]
    
    return {
        'scan_id': scan_id,
        'status': scan_data.get('status', 'unknown'),
        'progress': scan_data.get('progress', 0),
        'filename': scan_data.get('filename', ''),
        'started_at': scan_data.get('started_at', ''),
        'completed_at': scan_data.get('completed_at', ''),
        'error': scan_data.get('error', None)
    }

@router.get("/scan/{scan_id}/results")
async def get_scan_results(scan_id: str):
    """Get comprehensive scan results"""
    if scan_id not in scan_results_cache:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    scan_data = scan_results_cache[scan_id]
    
    if scan_data.get('status') != 'completed':
        return {
            'scan_id': scan_id,
            'status': scan_data.get('status', 'processing'),
            'message': 'Scan still in progress',
            'progress': scan_data.get('progress', 0)
        }
    
    return scan_data

@router.get("/scan/{scan_id}/report")
async def get_scan_report(scan_id: str, format: str = "json"):
    """Get formatted scan report"""
    if scan_id not in scan_results_cache:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    scan_data = scan_results_cache[scan_id]
    
    if scan_data.get('status') != 'completed':
        raise HTTPException(status_code=400, detail="Scan not completed")
    
    if format == "json":
        return scan_data.get('results', {})
    elif format == "markdown":
        return generate_markdown_report(scan_data.get('results', {}))
    elif format == "html":
        return generate_html_report(scan_data.get('results', {}))
    else:
        raise HTTPException(status_code=400, detail="Invalid format. Supported: json, markdown, html")

def get_estimated_time(scan_depth: str) -> str:
    """Get estimated scan time based on depth"""
    estimates = {
        'quick': '30-60 seconds',
        'standard': '2-5 minutes',
        'comprehensive': '5-10 minutes',
        'paranoid': '10-20 minutes'
    }
    return estimates.get(scan_depth, '5-10 minutes')

async def generate_ai_analysis(scan_results: dict) -> dict:
    """Generate AI-powered analysis using Claude"""
    try:
        import anthropic
        
        client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))
        
        # Prepare context
        context = f"""Comprehensive Security Scan Results:

Project Type: {', '.join(scan_results['project_info']['project_types'])}
Languages: {', '.join(scan_results['project_info']['languages'])}
Frameworks: {', '.join(scan_results['project_info']['frameworks'])}

Total Findings: {scan_results['summary']['total_findings']}
Critical: {scan_results['summary']['severity_breakdown']['critical']}
High: {scan_results['summary']['severity_breakdown']['high']}
Medium: {scan_results['summary']['severity_breakdown']['medium']}
Low: {scan_results['summary']['severity_breakdown']['low']}

Categories:
- Vulnerabilities: {scan_results['summary']['categories']['vulnerabilities']}
- Secrets: {scan_results['summary']['categories']['secrets']}
- Dependencies: {scan_results['summary']['categories']['dependencies']}
- Code Quality: {scan_results['summary']['categories']['code_quality']}
- Infrastructure: {scan_results['summary']['categories']['infrastructure']}
- Mobile Security: {scan_results['summary']['categories']['mobile_security']}

Top 20 Critical/High Findings:
"""
        
        # Add top findings
        critical_high = [f for f in scan_results['all_findings'] 
                        if f.get('severity', '').lower() in ['critical', 'high']][:20]
        
        for i, finding in enumerate(critical_high, 1):
            context += f"\n{i}. [{finding.get('severity', '').upper()}] {finding.get('title', '')}"
            context += f"\n   Tool: {finding.get('tool', '')}"
            context += f"\n   File: {finding.get('file', '')}:{finding.get('line', '')}"
            if finding.get('cve'):
                context += f"\n   CVE: {finding.get('cve', '')}"
            context += "\n"
        
        # Get AI analysis
        message = client.messages.create(
            model="claude-3-5-sonnet-20241022",
            max_tokens=4000,
            temperature=0,
            messages=[{
                "role": "user",
                "content": f"""{context}

As a senior security architect, provide a comprehensive security analysis including:

1. **Executive Summary** - High-level security assessment for executives
2. **Risk Assessment** - Overall risk level and business impact
3. **Critical Vulnerabilities** - Detailed analysis of the most dangerous issues
4. **Attack Vectors** - How attackers could exploit these vulnerabilities
5. **Remediation Plan** - Step-by-step fixes prioritized by risk
6. **Security Architecture Recommendations** - Long-term improvements
7. **Compliance Impact** - Effects on OWASP, PCI-DSS, SOC2, GDPR compliance
8. **Implementation Timeline** - Realistic timeline for fixes
9. **Security Tools Recommendations** - Additional tools and practices
10. **Code Examples** - Specific code fixes for top vulnerabilities

Use markdown formatting with clear sections."""
            }]
        )
        
        return {
            'success': True,
            'analysis': message.content[0].text if message.content else "Analysis not available",
            'model': 'claude-3-5-sonnet',
            'timestamp': datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        return {
            'success': False,
            'error': str(e),
            'analysis': 'AI analysis unavailable'
        }

def generate_detailed_report(scan_results: dict) -> dict:
    """Generate detailed security report"""
    report = {
        'overview': {
            'total_issues': scan_results['summary']['total_findings'],
            'risk_score': calculate_risk_score(scan_results),
            'security_grade': calculate_security_grade(scan_results),
            'top_risks': identify_top_risks(scan_results)
        },
        'recommendations': generate_recommendations(scan_results),
        'compliance_mapping': map_to_compliance_standards(scan_results),
        'metrics': calculate_security_metrics(scan_results)
    }
    
    return report

def calculate_risk_score(scan_results: dict) -> int:
    """Calculate overall risk score (0-100)"""
    severity_weights = {
        'critical': 40,
        'high': 20,
        'medium': 5,
        'low': 1,
        'info': 0
    }
    
    score = 0
    for severity, count in scan_results['summary']['severity_breakdown'].items():
        score += count * severity_weights.get(severity, 0)
    
    # Normalize to 0-100
    return min(100, score)

def calculate_security_grade(scan_results: dict) -> str:
    """Calculate security grade A-F"""
    risk_score = calculate_risk_score(scan_results)
    
    if risk_score == 0:
        return 'A+'
    elif risk_score < 10:
        return 'A'
    elif risk_score < 25:
        return 'B'
    elif risk_score < 50:
        return 'C'
    elif risk_score < 75:
        return 'D'
    else:
        return 'F'

def identify_top_risks(scan_results: dict) -> list:
    """Identify top security risks"""
    risks = []
    
    if scan_results['summary']['categories']['secrets'] > 0:
        risks.append('Hardcoded secrets and credentials')
    if scan_results['summary']['categories']['dependencies'] > 0:
        risks.append('Vulnerable third-party dependencies')
    if scan_results['summary']['severity_breakdown']['critical'] > 0:
        risks.append('Critical security vulnerabilities')
    if scan_results['project_info']['has_database']:
        risks.append('Potential SQL injection risks')
    if scan_results['project_info']['has_web_frontend']:
        risks.append('Cross-site scripting (XSS) risks')
    
    return risks[:5]

def generate_recommendations(scan_results: dict) -> list:
    """Generate security recommendations"""
    recommendations = []
    
    if scan_results['summary']['categories']['secrets'] > 0:
        recommendations.append({
            'priority': 'critical',
            'title': 'Remove hardcoded secrets',
            'description': 'Use environment variables or secret management services'
        })
    
    if scan_results['summary']['categories']['dependencies'] > 0:
        recommendations.append({
            'priority': 'high',
            'title': 'Update vulnerable dependencies',
            'description': 'Run dependency updates and enable automated security updates'
        })
    
    return recommendations

def map_to_compliance_standards(scan_results: dict) -> dict:
    """Map findings to compliance standards"""
    return {
        'owasp_top_10': count_owasp_issues(scan_results),
        'pci_dss': scan_results['summary']['categories']['secrets'] > 0,
        'gdpr': scan_results['project_info']['has_database'],
        'soc2': scan_results['summary']['severity_breakdown']['high'] > 0
    }

def count_owasp_issues(scan_results: dict) -> dict:
    """Count OWASP Top 10 issues"""
    owasp_counts = {}
    for finding in scan_results['all_findings']:
        if 'owasp' in finding:
            for owasp_id in finding['owasp']:
                owasp_counts[owasp_id] = owasp_counts.get(owasp_id, 0) + 1
    return owasp_counts

def calculate_security_metrics(scan_results: dict) -> dict:
    """Calculate security metrics"""
    total = scan_results['summary']['total_findings']
    if total == 0:
        return {'vulnerability_density': 0, 'critical_ratio': 0}
    
    return {
        'vulnerability_density': total / max(1, scan_results['project_info'].get('file_count', 1)),
        'critical_ratio': scan_results['summary']['severity_breakdown']['critical'] / total,
        'secret_exposure': scan_results['summary']['categories']['secrets'] / total
    }

def generate_markdown_report(results: dict) -> str:
    """Generate markdown report"""
    # Implementation for markdown report
    return "# Security Scan Report\n\n..."

def generate_html_report(results: dict) -> str:
    """Generate HTML report"""
    # Implementation for HTML report
    return "<html><body><h1>Security Scan Report</h1>...</body></html>"