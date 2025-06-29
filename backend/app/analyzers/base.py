from abc import ABC, abstractmethod
from typing import List, Dict, Any
import os
import subprocess
import json
import logging

logger = logging.getLogger(__name__)

class BaseAnalyzer(ABC):
    """Base class for all code analyzers"""
    
    def __init__(self):
        self.name = self.__class__.__name__
        self.supported_extensions = []
    
    @abstractmethod
    async def analyze(self, code_path: str) -> List[Dict[str, Any]]:
        """Analyze code and return list of findings"""
        pass
    
    def _run_command(self, command: List[str], cwd: str = None) -> subprocess.CompletedProcess:
        """Run a command and return the result"""
        try:
            result = subprocess.run(
                command,
                cwd=cwd,
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout
            )
            return result
        except subprocess.TimeoutExpired:
            logger.error(f"Command timed out: {' '.join(command)}")
            raise
        except Exception as e:
            logger.error(f"Error running command: {e}")
            raise
    
    def _find_files(self, code_path: str, extensions: List[str]) -> List[str]:
        """Find all files with given extensions"""
        files = []
        for root, dirs, filenames in os.walk(code_path):
            # Skip hidden directories
            dirs[:] = [d for d in dirs if not d.startswith('.')]
            
            for filename in filenames:
                if any(filename.endswith(ext) for ext in extensions):
                    files.append(os.path.join(root, filename))
        
        return files
    
    def _parse_sarif(self, sarif_output: str) -> List[Dict[str, Any]]:
        """Parse SARIF output into standardized format"""
        results = []
        try:
            sarif = json.loads(sarif_output)
            for run in sarif.get('runs', []):
                for result in run.get('results', []):
                    finding = {
                        'rule_id': result.get('ruleId'),
                        'title': result.get('message', {}).get('text', 'Unknown issue'),
                        'severity': self._map_severity(result.get('level', 'warning')),
                        'analyzer': self.name
                    }
                    
                    # Location information
                    locations = result.get('locations', [])
                    if locations:
                        physical_location = locations[0].get('physicalLocation', {})
                        artifact_location = physical_location.get('artifactLocation', {})
                        region = physical_location.get('region', {})
                        
                        finding['file_path'] = artifact_location.get('uri')
                        finding['line_number'] = region.get('startLine')
                        finding['column_number'] = region.get('startColumn')
                        finding['code_snippet'] = region.get('snippet', {}).get('text')
                    
                    results.append(finding)
        
        except json.JSONDecodeError:
            logger.error("Failed to parse SARIF output")
        
        return results
    
    def _map_severity(self, level: str) -> str:
        """Map tool-specific severity to our standard"""
        mapping = {
            'error': 'high',
            'warning': 'medium',
            'note': 'low',
            'none': 'info'
        }
        return mapping.get(level.lower(), 'medium')