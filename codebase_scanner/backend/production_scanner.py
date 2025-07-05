#!/usr/bin/env python3
"""
Production Scanner - Optimized for real-world use with 15 tools
"""

import asyncio
import json
import subprocess
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any

from all_tools_scanner import AllToolsScanner


class ProductionScanner(AllToolsScanner):
    """Production-ready scanner optimized for performance"""
    
    def __init__(self, repo_path: str):
        super().__init__(repo_path, force_all_tools=True)
        
    async def scan_repository(self) -> Dict[str, Any]:
        """Run production scan with all 15 tools"""
        print(f"[*] Starting PRODUCTION security scan")
        print(f"[*] Repository: {self.repo_path}")
        print(f"[*] Tools configured: 15")
        print(f"[*] Scan ID: {self.scan_id}")
        print("[*] This scan uses all production-ready tools")
        
        # Perform deep analysis
        await self.analyze_codebase_deeply()
        
        # Get tools
        tools = self.detect_and_configure_tools()
        
        print(f"\n[*] Running {len(tools)} security tools...")
        
        # Run tools with progress reporting
        results = {
            "scan_id": self.scan_id,
            "repository": str(self.repo_path),
            "scan_time": datetime.now().isoformat(),
            "tool_results": [],
            "vulnerabilities": [],
            "metrics": self.metrics,
            "enhanced_analysis": self.file_analysis
        }
        
        # Run each tool and report progress
        for i, tool in enumerate(tools):
            print(f"\n[{i+1}/{len(tools)}] Running {tool.name}...")
            result = await self.run_tool(tool)
            results["tool_results"].append(result)
            
            if result["status"] == "success":
                print(f"    ✓ {tool.name} completed - {len(result.get('findings', []))} findings")
            elif result["status"] == "not_installed":
                print(f"    ⚠ {tool.name} not installed in this environment")
            else:
                print(f"    ✗ {tool.name} failed: {result.get('error', 'Unknown error')}")
                
        # Aggregate findings
        all_findings = []
        for result in results["tool_results"]:
            if result["status"] == "success":
                all_findings.extend(result.get("findings", []))
                
        # Deduplicate and score
        self.vulnerabilities = self.deduplicate_findings(all_findings)
        results["vulnerabilities"] = [vuln.__dict__ for vuln in self.vulnerabilities]
        
        # Update metrics
        self.metrics["end_time"] = datetime.now()
        self.metrics["total_vulnerabilities"] = len(self.vulnerabilities)
        self.metrics["critical_count"] = sum(1 for v in self.vulnerabilities if v.severity.value == "CRITICAL")
        self.metrics["high_count"] = sum(1 for v in self.vulnerabilities if v.severity.value == "HIGH")
        self.metrics["sensitive_files"] = len(self.file_analysis["stats"]["sensitive_files"])
        self.metrics["api_endpoints"] = len(self.file_analysis["patterns"]["api_endpoints"])
        self.metrics["total_tools_available"] = 15
        self.metrics["tools_installed"] = sum(1 for r in results["tool_results"] if r["status"] != "not_installed")
        
        results["metrics"] = self.metrics
        
        # Generate summary
        print(f"\n[*] Scan Summary:")
        print(f"    - Total tools available: 15")
        print(f"    - Tools installed: {self.metrics['tools_installed']}")
        print(f"    - Tools successfully run: {self.metrics['tools_run']}")
        print(f"    - Total vulnerabilities: {self.metrics['total_vulnerabilities']}")
        print(f"    - Critical: {self.metrics['critical_count']}")
        print(f"    - High: {self.metrics['high_count']}")
        print(f"    - Sensitive files: {self.metrics['sensitive_files']}")
        print(f"    - API endpoints: {self.metrics['api_endpoints']}")
        
        return results


async def main():
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python production_scanner.py <repository_path>")
        sys.exit(1)
        
    repo_path = sys.argv[1]
    scanner = ProductionScanner(repo_path)
    
    print("=" * 70)
    print("PRODUCTION SECURITY SCANNER - 15 TOOLS")
    print("=" * 70)
    
    # Run scan
    results = await scanner.scan_repository()
    
    # Generate report
    print(f"\n[*] Generating comprehensive security report...")
    report_path = scanner.generate_enhanced_report(results)
    
    print(f"\n[✓] Production scan complete!")
    print(f"[✓] Report generated: {report_path}")
    print(f"[✓] Report location: {report_path}")
    
    # Save raw results
    results_file = scanner.results_dir / "scan_results.json"
    with open(results_file, 'w') as f:
        json.dump(results, f, indent=2, default=str)
    print(f"[✓] Raw results saved: {results_file}")


if __name__ == "__main__":
    asyncio.run(main())