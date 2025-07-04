"""
AI Analysis API endpoints for vulnerability analysis using Claude.
"""

from typing import List, Dict, Any, Optional
from fastapi import APIRouter, HTTPException, Depends, BackgroundTasks
from pydantic import BaseModel
from supabase import Client
import anthropic
import os
from datetime import datetime

from src.database import get_supabase_client
from src.dependencies import get_current_user
from src.models.user import User
from app.tasks.ai_tasks import analyze_vulnerability_task, batch_analyze_task

router = APIRouter()

# Initialize Anthropic client
anthropic_client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))


class VulnerabilityAnalysisRequest(BaseModel):
    vulnerability_id: str
    cwe_id: str
    vulnerability_type: str
    owasp_category: str
    file_path: str
    line_number: int
    code_snippet: str
    language: str
    severity: str
    context: str


class BatchAnalysisRequest(BaseModel):
    scan_id: str
    vulnerability_ids: List[str]


class AnalysisResponse(BaseModel):
    vulnerability_id: str
    risk_description: str
    plain_english_explanation: str
    fix_suggestions: List[str]
    code_fix: Optional[str]
    compliance_violations: Dict[str, Any]
    remediation_steps: List[str]
    severity_justification: str
    references: List[str]
    analyzed_at: str


@router.post("/analyze-vulnerability", response_model=AnalysisResponse)
async def analyze_vulnerability(
    request: VulnerabilityAnalysisRequest,
    current_user: User = Depends(get_current_user),
    supabase: Client = Depends(get_supabase_client)
):
    """
    Analyze a single vulnerability using Claude AI.
    """
    try:
        # Create the analysis prompt
        prompt = f"""Analyze this security vulnerability and provide detailed recommendations:

CWE ID: {request.cwe_id}
Type: {request.vulnerability_type}
OWASP Category: {request.owasp_category}
Severity: {request.severity}
File: {request.file_path}
Line: {request.line_number}
Language: {request.language}

Code snippet:
```{request.language}
{request.code_snippet}
```

Context: {request.context}

Please provide:
1. A detailed risk description explaining why this is dangerous
2. A plain English explanation for non-technical stakeholders
3. Specific fix suggestions (list at least 3)
4. A code fix example showing the corrected code
5. Any compliance violations (OWASP, PCI-DSS, GDPR, etc.)
6. Step-by-step remediation instructions
7. Justification for the severity rating
8. References and links for further reading

Format your response as a JSON object with these exact keys:
- risk_description
- plain_english_explanation
- fix_suggestions (array)
- code_fix
- compliance_violations (object)
- remediation_steps (array)
- severity_justification
- references (array)
"""

        # Call Claude API
        message = anthropic_client.messages.create(
            model="claude-3-sonnet-20240229",
            max_tokens=2000,
            temperature=0,
            system="You are a senior security engineer analyzing code vulnerabilities. Provide detailed, actionable security recommendations in JSON format.",
            messages=[
                {
                    "role": "user",
                    "content": prompt
                }
            ]
        )
        
        # Parse the response
        import json
        response_text = message.content[0].text
        
        # Extract JSON from the response
        json_start = response_text.find('{')
        json_end = response_text.rfind('}') + 1
        if json_start != -1 and json_end > json_start:
            response_text = response_text[json_start:json_end]
        
        analysis_result = json.loads(response_text)
        
        # Add metadata
        analysis_result['vulnerability_id'] = request.vulnerability_id
        analysis_result['analyzed_at'] = datetime.utcnow().isoformat()
        
        # Store in database
        supabase.table("ai_analyses").insert({
            "vulnerability_id": request.vulnerability_id,
            "analysis": analysis_result,
            "user_id": current_user.id,
            "created_at": datetime.utcnow().isoformat()
        }).execute()
        
        return AnalysisResponse(**analysis_result)
        
    except json.JSONDecodeError as e:
        raise HTTPException(status_code=500, detail=f"Failed to parse AI response: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"AI analysis failed: {str(e)}")


@router.post("/batch-analyze")
async def batch_analyze_vulnerabilities(
    request: BatchAnalysisRequest,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_user),
    supabase: Client = Depends(get_supabase_client)
):
    """
    Analyze multiple vulnerabilities in batch using background tasks.
    """
    try:
        # Verify scan ownership
        scan = supabase.table("scans").select("*").eq("id", request.scan_id).eq("user_id", current_user.id).single().execute()
        if not scan.data:
            raise HTTPException(status_code=404, detail="Scan not found")
        
        # Get vulnerabilities
        vulnerabilities = supabase.table("scan_results")\
            .select("*")\
            .in_("id", request.vulnerability_ids)\
            .eq("scan_id", request.scan_id)\
            .execute()
        
        if not vulnerabilities.data:
            raise HTTPException(status_code=404, detail="No vulnerabilities found")
        
        # Queue batch analysis task
        task = batch_analyze_task.delay(vulnerabilities.data, request.scan_id)
        
        # Update scan to indicate AI analysis is in progress
        supabase.table("scans").update({
            "ai_analysis_status": "in_progress",
            "ai_analysis_task_id": task.id
        }).eq("id", request.scan_id).execute()
        
        return {
            "message": f"Batch analysis started for {len(vulnerabilities.data)} vulnerabilities",
            "task_id": task.id,
            "scan_id": request.scan_id
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to start batch analysis: {str(e)}")


@router.get("/analysis/{vulnerability_id}")
async def get_vulnerability_analysis(
    vulnerability_id: str,
    current_user: User = Depends(get_current_user),
    supabase: Client = Depends(get_supabase_client)
):
    """
    Get AI analysis for a specific vulnerability.
    """
    try:
        # Get the analysis
        analysis = supabase.table("ai_analyses")\
            .select("*")\
            .eq("vulnerability_id", vulnerability_id)\
            .order("created_at", desc=True)\
            .limit(1)\
            .execute()
        
        if not analysis.data:
            raise HTTPException(status_code=404, detail="Analysis not found")
        
        return analysis.data[0]["analysis"]
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get analysis: {str(e)}")


@router.get("/scan/{scan_id}/analyses")
async def get_scan_analyses(
    scan_id: str,
    current_user: User = Depends(get_current_user),
    supabase: Client = Depends(get_supabase_client)
):
    """
    Get all AI analyses for a scan.
    """
    try:
        # Verify scan ownership
        scan = supabase.table("scans").select("id").eq("id", scan_id).eq("user_id", current_user.id).single().execute()
        if not scan.data:
            raise HTTPException(status_code=404, detail="Scan not found")
        
        # Get all vulnerabilities for the scan
        vulnerabilities = supabase.table("scan_results").select("id").eq("scan_id", scan_id).execute()
        vuln_ids = [v["id"] for v in vulnerabilities.data]
        
        # Get analyses
        analyses = supabase.table("ai_analyses")\
            .select("*")\
            .in_("vulnerability_id", vuln_ids)\
            .execute()
        
        return {
            "scan_id": scan_id,
            "total_vulnerabilities": len(vuln_ids),
            "analyzed_count": len(analyses.data),
            "analyses": analyses.data
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get scan analyses: {str(e)}")


@router.post("/scan/{scan_id}/analyze-all")
async def analyze_all_scan_vulnerabilities(
    scan_id: str,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_user),
    supabase: Client = Depends(get_supabase_client)
):
    """
    Analyze all vulnerabilities in a scan.
    """
    try:
        # Verify scan ownership
        scan = supabase.table("scans").select("*").eq("id", scan_id).eq("user_id", current_user.id).single().execute()
        if not scan.data:
            raise HTTPException(status_code=404, detail="Scan not found")
        
        # Get all vulnerabilities
        vulnerabilities = supabase.table("scan_results")\
            .select("*")\
            .eq("scan_id", scan_id)\
            .execute()
        
        if not vulnerabilities.data:
            return {"message": "No vulnerabilities to analyze"}
        
        # Filter out already analyzed vulnerabilities
        vuln_ids = [v["id"] for v in vulnerabilities.data]
        existing_analyses = supabase.table("ai_analyses")\
            .select("vulnerability_id")\
            .in_("vulnerability_id", vuln_ids)\
            .execute()
        
        analyzed_ids = {a["vulnerability_id"] for a in existing_analyses.data}
        unanalyzed = [v for v in vulnerabilities.data if v["id"] not in analyzed_ids]
        
        if not unanalyzed:
            return {"message": "All vulnerabilities already analyzed"}
        
        # Queue batch analysis task
        task = batch_analyze_task.delay(unanalyzed, scan_id)
        
        # Update scan status
        supabase.table("scans").update({
            "ai_analysis_status": "in_progress",
            "ai_analysis_task_id": task.id
        }).eq("id", scan_id).execute()
        
        return {
            "message": f"Started analysis for {len(unanalyzed)} vulnerabilities",
            "task_id": task.id,
            "scan_id": scan_id,
            "total_vulnerabilities": len(vulnerabilities.data),
            "already_analyzed": len(analyzed_ids),
            "to_analyze": len(unanalyzed)
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to start analysis: {str(e)}")