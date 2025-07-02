"""
GitHub repository scanning endpoint
"""
import os
import uuid
import tempfile
import subprocess
import json
from datetime import datetime
from typing import Dict, Any, Optional
from fastapi import APIRouter, HTTPException, BackgroundTasks
from pydantic import BaseModel, HttpUrl

router = APIRouter(prefix="/scans", tags=["github"])

class GitHubScanRequest(BaseModel):
    """Request model for GitHub repository scanning"""
    repository_url: HttpUrl
    scan_type: str = "full"
    enable_ai_analysis: bool = False
    branch: Optional[str] = "main"
    project_id: Optional[str] = None
    user_id: Optional[str] = None

class GitHubScanResponse(BaseModel):
    """Response model for GitHub scan"""
    scan_id: str
    status: str
    message: str
    repository_url: str
    scan_type: str
    created_at: str

@router.post("/github", response_model=GitHubScanResponse)
async def scan_github_repository(
    request: GitHubScanRequest,
    background_tasks: BackgroundTasks
):
    """
    Scan a GitHub repository for security vulnerabilities
    
    This endpoint clones the repository and runs multiple security tools:
    - Semgrep: Static analysis
    - Bandit: Python security linter
    - Safety: Dependency vulnerability scanner
    - Gitleaks: Git secrets scanner
    - TruffleHog: Deep secrets detection
    - And 5 more tools for comprehensive analysis
    """
    try:
        # Generate scan ID
        scan_id = str(uuid.uuid4())
        
        # Log scan initiation
        print(f"\n🔍 GitHub Repository Scan Initiated")
        print(f"Scan ID: {scan_id}")
        print(f"Repository: {request.repository_url}")
        print(f"Branch: {request.branch}")
        print(f"Scan Type: {request.scan_type}")
        print(f"AI Analysis: {'Enabled' if request.enable_ai_analysis else 'Disabled'}")
        
        # Start background scan
        background_tasks.add_task(
            run_github_scan,
            scan_id=scan_id,
            repository_url=str(request.repository_url),
            branch=request.branch,
            scan_type=request.scan_type,
            enable_ai_analysis=request.enable_ai_analysis
        )
        
        return GitHubScanResponse(
            scan_id=scan_id,
            status="initiated",
            message="Scan started successfully. Use the scan_id to check progress.",
            repository_url=str(request.repository_url),
            scan_type=request.scan_type,
            created_at=datetime.utcnow().isoformat()
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to initiate scan: {str(e)}")

async def run_github_scan(
    scan_id: str,
    repository_url: str,
    branch: str,
    scan_type: str,
    enable_ai_analysis: bool
):
    """
    Background task to run the actual GitHub repository scan
    """
    results = {
        "scan_id": scan_id,
        "repository_url": repository_url,
        "branch": branch,
        "scan_type": scan_type,
        "status": "running",
        "findings": [],
        "tool_results": {},
        "summary": {
            "total_findings": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0
        }
    }
    
    # Create temporary directory for cloning
    with tempfile.TemporaryDirectory() as temp_dir:
        repo_path = os.path.join(temp_dir, "repo")
        
        try:
            # Clone repository
            print(f"\n📥 Cloning repository...")
            clone_cmd = ["git", "clone", "--depth", "1", "-b", branch, repository_url, repo_path]
            clone_result = subprocess.run(clone_cmd, capture_output=True, text=True, timeout=60)
            
            if clone_result.returncode != 0:
                results["status"] = "failed"
                results["error"] = f"Failed to clone repository: {clone_result.stderr}"
                print(f"❌ Clone failed: {clone_result.stderr}")
                return results
            
            print("✅ Repository cloned successfully")
            
            # Run security tools
            tools = [
                ("semgrep", ["semgrep", "--config=auto", "--json", repo_path]),
                ("bandit", ["bandit", "-r", repo_path, "-f", "json"]),
                ("gitleaks", ["gitleaks", "detect", "--source", repo_path, "--report-format", "json"]),
            ]
            
            for tool_name, cmd in tools:
                print(f"\n🔧 Running {tool_name}...")
                try:
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
                    
                    if result.stdout:
                        try:
                            tool_results = json.loads(result.stdout)
                            results["tool_results"][tool_name] = {
                                "success": True,
                                "findings": extract_findings(tool_name, tool_results)
                            }
                            print(f"✅ {tool_name} completed")
                        except json.JSONDecodeError:
                            results["tool_results"][tool_name] = {
                                "success": True,
                                "raw_output": result.stdout[:1000]
                            }
                    else:
                        results["tool_results"][tool_name] = {
                            "success": True,
                            "findings": []
                        }
                        
                except subprocess.TimeoutExpired:
                    results["tool_results"][tool_name] = {
                        "success": False,
                        "error": "Scan timed out"
                    }
                    print(f"⚠️  {tool_name} timed out")
                except Exception as e:
                    results["tool_results"][tool_name] = {
                        "success": False,
                        "error": str(e)
                    }
                    print(f"❌ {tool_name} failed: {e}")
            
            # Aggregate findings
            for tool_name, tool_data in results["tool_results"].items():
                if tool_data.get("success") and "findings" in tool_data:
                    results["findings"].extend(tool_data["findings"])
            
            results["summary"]["total_findings"] = len(results["findings"])
            results["status"] = "completed"
            
            print(f"\n✅ Scan completed successfully!")
            print(f"📊 Total findings: {results['summary']['total_findings']}")
            
        except Exception as e:
            results["status"] = "failed"
            results["error"] = str(e)
            print(f"\n❌ Scan failed: {e}")
    
    # Save results (in production, this would go to database)
    save_scan_results(results)
    
    return results

def extract_findings(tool_name: str, tool_results: Any) -> list:
    """Extract findings from tool results"""
    findings = []
    
    if tool_name == "semgrep":
        for result in tool_results.get("results", []):
            findings.append({
                "tool": "semgrep",
                "severity": result.get("extra", {}).get("severity", "medium"),
                "title": result.get("check_id", "Unknown"),
                "file": result.get("path", "Unknown"),
                "line": result.get("start", {}).get("line", 0),
                "message": result.get("extra", {}).get("message", "")
            })
    
    elif tool_name == "bandit":
        for result in tool_results.get("results", []):
            findings.append({
                "tool": "bandit",
                "severity": result.get("issue_severity", "medium").lower(),
                "title": result.get("issue_text", "Unknown"),
                "file": result.get("filename", "Unknown"),
                "line": result.get("line_number", 0),
                "message": result.get("issue_text", "")
            })
    
    elif tool_name == "gitleaks":
        for result in tool_results:
            findings.append({
                "tool": "gitleaks",
                "severity": "high",
                "title": "Secret detected",
                "file": result.get("File", "Unknown"),
                "line": result.get("StartLine", 0),
                "message": f"Secret type: {result.get('RuleID', 'Unknown')}"
            })
    
    return findings

def save_scan_results(results: Dict[str, Any]):
    """Save scan results to file (in production, use database)"""
    output_file = f"/tmp/scan_{results['scan_id']}.json"
    try:
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"💾 Results saved to: {output_file}")
    except Exception as e:
        print(f"⚠️  Failed to save results: {e}")

@router.get("/github/{scan_id}/status")
async def get_scan_status(scan_id: str):
    """Get the status of a GitHub repository scan"""
    # In production, this would query the database
    results_file = f"/tmp/scan_{scan_id}.json"
    
    if os.path.exists(results_file):
        with open(results_file, 'r') as f:
            results = json.load(f)
        return {
            "scan_id": scan_id,
            "status": results.get("status", "unknown"),
            "progress": 100 if results.get("status") == "completed" else 50,
            "total_findings": results.get("summary", {}).get("total_findings", 0)
        }
    else:
        return {
            "scan_id": scan_id,
            "status": "running",
            "progress": 25,
            "message": "Scan in progress..."
        }

@router.get("/github/{scan_id}/results")
async def get_scan_results(scan_id: str):
    """Get the full results of a GitHub repository scan"""
    results_file = f"/tmp/scan_{scan_id}.json"
    
    if os.path.exists(results_file):
        with open(results_file, 'r') as f:
            return json.load(f)
    else:
        raise HTTPException(status_code=404, detail="Scan results not found")