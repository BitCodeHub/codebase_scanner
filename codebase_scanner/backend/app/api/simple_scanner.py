"""
Simple synchronous scanner endpoint for testing
"""
from fastapi import APIRouter, HTTPException, UploadFile, File
import tempfile
import os
import re
import json

router = APIRouter()

@router.post("/test/simple-scan")
async def simple_scan(file: UploadFile = File(...)):
    """Simple synchronous scan for testing"""
    
    # Read file content
    content = await file.read()
    text = content.decode('utf-8', errors='ignore')
    
    findings = []
    
    # Simple regex patterns for common secrets
    patterns = {
        'api_key': r'(?i)(api[_-]?key|apikey)\s*[:=]\s*["\']([^"\']+)["\']',
        'password': r'(?i)(password|passwd|pwd)\s*[:=]\s*["\']([^"\']+)["\']',
        'secret': r'(?i)(secret[_-]?key|secret)\s*[:=]\s*["\']([^"\']+)["\']',
        'aws_key': r'AKIA[0-9A-Z]{16}',
        'token': r'(?i)(token|auth[_-]?token)\s*[:=]\s*["\']([^"\']+)["\']'
    }
    
    lines = text.split('\n')
    for line_num, line in enumerate(lines, 1):
        for pattern_name, pattern in patterns.items():
            matches = re.finditer(pattern, line)
            for match in matches:
                findings.append({
                    'type': pattern_name,
                    'line': line_num,
                    'text': line.strip()[:100],
                    'severity': 'high' if 'key' in pattern_name or 'secret' in pattern_name else 'medium'
                })
    
    # Check for dangerous functions
    dangerous_patterns = {
        'eval': r'\beval\s*\(',
        'exec': r'\bexec\s*\(',
        'pickle': r'\bpickle\.loads?\s*\(',
        'sql_injection': r'["\'].*SELECT.*FROM.*["\'].*\+|f["\'].*SELECT.*FROM.*\{',
        'command_injection': r'subprocess\.(call|run|Popen).*shell\s*=\s*True',
        'weak_crypto': r'hashlib\.(md5|sha1)\s*\('
    }
    
    for line_num, line in enumerate(lines, 1):
        for vuln_name, pattern in dangerous_patterns.items():
            if re.search(pattern, line):
                findings.append({
                    'type': vuln_name,
                    'line': line_num,
                    'text': line.strip()[:100],
                    'severity': 'high' if 'injection' in vuln_name else 'medium'
                })
    
    # Test Anthropic API
    ai_status = "disabled"
    try:
        api_key = os.getenv("ANTHROPIC_API_KEY")
        if api_key:
            import anthropic
            client = anthropic.Anthropic(api_key=api_key)
            # Quick test message
            msg = client.messages.create(
                model="claude-3-5-sonnet-20241022",
                max_tokens=100,
                messages=[{"role": "user", "content": "Say 'API working' in 3 words or less"}]
            )
            ai_status = "working" if msg.content else "error"
    except Exception as e:
        ai_status = f"error: {str(e)[:50]}"
    
    return {
        'filename': file.filename,
        'file_size': len(content),
        'total_findings': len(findings),
        'findings': findings[:10],  # First 10 findings
        'severity_summary': {
            'high': len([f for f in findings if f['severity'] == 'high']),
            'medium': len([f for f in findings if f['severity'] == 'medium']),
            'low': len([f for f in findings if f['severity'] == 'low'])
        },
        'ai_status': ai_status,
        'scanner_status': 'working'
    }