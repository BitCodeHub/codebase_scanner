import os
import asyncio
from typing import List, Dict, Any
import openai
from anthropic import Anthropic
from app.config import settings
import logging

logger = logging.getLogger(__name__)

class AIAnalyzer:
    """AI-powered code vulnerability analyzer"""
    
    def __init__(self):
        self.openai_client = openai.AsyncOpenAI(api_key=settings.openai_api_key) if settings.openai_api_key else None
        self.anthropic_client = Anthropic(api_key=settings.anthropic_api_key) if settings.anthropic_api_key else None
    
    async def analyze(self, code_path: str) -> List[Dict[str, Any]]:
        """Analyze code using AI for security vulnerabilities"""
        results = []
        
        # Get important files to analyze
        files_to_analyze = self._get_important_files(code_path)
        
        # Analyze files in batches
        for file_path in files_to_analyze[:10]:  # Limit to 10 files for cost control
            try:
                file_results = await self._analyze_file(file_path)
                results.extend(file_results)
            except Exception as e:
                logger.error(f"Error analyzing {file_path}: {e}")
        
        return results
    
    def _get_important_files(self, code_path: str) -> List[str]:
        """Get list of important files to analyze"""
        important_files = []
        important_patterns = [
            'auth', 'login', 'password', 'token', 'secret',
            'api', 'database', 'db', 'config', 'settings',
            'payment', 'stripe', 'crypto', 'hash'
        ]
        
        for root, dirs, files in os.walk(code_path):
            dirs[:] = [d for d in dirs if not d.startswith('.')]
            
            for file in files:
                # Check if file name contains important patterns
                if any(pattern in file.lower() for pattern in important_patterns):
                    file_path = os.path.join(root, file)
                    if os.path.getsize(file_path) < 100000:  # Skip large files
                        important_files.append(file_path)
        
        return important_files
    
    async def _analyze_file(self, file_path: str) -> List[Dict[str, Any]]:
        """Analyze a single file for vulnerabilities"""
        results = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Skip if file is too large
            if len(content) > 50000:
                return results
            
            # Use available AI service
            if self.anthropic_client:
                vulnerabilities = await self._analyze_with_claude(content, file_path)
            elif self.openai_client:
                vulnerabilities = await self._analyze_with_openai(content, file_path)
            else:
                return results
            
            # Convert AI response to standard format
            for vuln in vulnerabilities:
                result = {
                    'rule_id': f"ai-{vuln.get('type', 'unknown')}",
                    'title': vuln.get('title', 'Potential security issue'),
                    'description': vuln.get('description'),
                    'severity': vuln.get('severity', 'medium'),
                    'category': 'security',
                    'file_path': file_path,
                    'line_number': vuln.get('line_number'),
                    'vulnerability_type': vuln.get('type'),
                    'confidence': vuln.get('confidence', 'medium'),
                    'fix_recommendation': vuln.get('fix'),
                    'ai_generated_fix': vuln.get('code_fix'),
                    'analyzer': 'ai',
                    'references': vuln.get('references', [])
                }
                results.append(result)
        
        except Exception as e:
            logger.error(f"Error in AI analysis: {e}")
        
        return results
    
    async def _analyze_with_claude(self, content: str, file_path: str) -> List[Dict[str, Any]]:
        """Analyze code using Claude"""
        prompt = f"""Analyze the following code for security vulnerabilities. Focus on:
- SQL injection
- XSS vulnerabilities
- Authentication/authorization issues
- Sensitive data exposure
- Insecure configurations
- Cryptographic weaknesses

File: {os.path.basename(file_path)}

Code:
```
{content[:10000]}
```

Return a JSON array of vulnerabilities found. Each vulnerability should have:
- type: vulnerability type (e.g., "sql_injection", "xss")
- title: short description
- description: detailed explanation
- severity: critical/high/medium/low
- line_number: approximate line number if identifiable
- confidence: high/medium/low
- fix: recommendation to fix
- code_fix: suggested code fix if applicable
- references: list of relevant CWE IDs or OWASP references

If no vulnerabilities found, return empty array []."""

        response = self.anthropic_client.messages.create(
            model="claude-3-opus-20240229",
            max_tokens=4000,
            messages=[{"role": "user", "content": prompt}]
        )
        
        try:
            import json
            # Extract JSON from response
            response_text = response.content[0].text
            start_idx = response_text.find('[')
            end_idx = response_text.rfind(']') + 1
            if start_idx != -1 and end_idx != 0:
                json_str = response_text[start_idx:end_idx]
                return json.loads(json_str)
        except:
            pass
        
        return []
    
    async def _analyze_with_openai(self, content: str, file_path: str) -> List[Dict[str, Any]]:
        """Analyze code using OpenAI"""
        prompt = f"""Analyze the following code for security vulnerabilities. Focus on:
- SQL injection
- XSS vulnerabilities  
- Authentication/authorization issues
- Sensitive data exposure
- Insecure configurations
- Cryptographic weaknesses

File: {os.path.basename(file_path)}

Code:
```
{content[:10000]}
```

Return a JSON array of vulnerabilities found. Each vulnerability should have:
- type: vulnerability type (e.g., "sql_injection", "xss")
- title: short description
- description: detailed explanation
- severity: critical/high/medium/low
- line_number: approximate line number if identifiable
- confidence: high/medium/low
- fix: recommendation to fix
- code_fix: suggested code fix if applicable
- references: list of relevant CWE IDs or OWASP references

If no vulnerabilities found, return empty array []."""

        response = await self.openai_client.chat.completions.create(
            model="gpt-4",
            messages=[{"role": "user", "content": prompt}],
            response_format={"type": "json_object"}
        )
        
        try:
            import json
            result = json.loads(response.choices[0].message.content)
            return result.get('vulnerabilities', [])
        except:
            return []