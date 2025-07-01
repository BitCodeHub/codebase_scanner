#!/usr/bin/env python3
"""
Demo script for testing AI-powered security analysis capabilities.
Run this script to see how Claude AI analyzes security findings.
"""

import asyncio
import json
import os
from app.main import generate_ai_security_insights

async def demo_ai_analysis():
    """Demonstrate AI security analysis with sample findings"""
    
    print("🤖 AI-Powered Security Analysis Demo")
    print("=" * 50)
    
    # Check if Anthropic API key is configured
    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        print("❌ ANTHROPIC_API_KEY not found in environment variables")
        print("Please set your Anthropic API key to enable AI analysis")
        print("export ANTHROPIC_API_KEY=your-api-key")
        return
    
    print(f"✅ Anthropic API key configured: {api_key[:10]}...")
    print()
    
    # Sample security findings (realistic mobile app vulnerabilities)
    sample_findings = [
        {
            "check_id": "javascript.jwt.security.jwt-hardcoded-secret",
            "path": "src/auth/jwt.js",
            "start": {"line": 15, "col": 20},
            "end": {"line": 15, "col": 45},
            "message": "Hardcoded JWT secret detected",
            "severity": "ERROR",
            "extra": {
                "message": "JWT secret 'mySecretKey123' is hardcoded in source code",
                "metavars": {
                    "$SECRET": {
                        "abstract_content": "mySecretKey123"
                    }
                }
            }
        },
        {
            "check_id": "javascript.crypto.insecure-random",
            "path": "src/utils/crypto.js", 
            "start": {"line": 42, "col": 15},
            "end": {"line": 42, "col": 35},
            "message": "Insecure random number generation",
            "severity": "WARNING",
            "extra": {
                "message": "Math.random() is not cryptographically secure for generating tokens"
            }
        },
        {
            "check_id": "javascript.express.security.express-cookie-session-no-httponly",
            "path": "src/middleware/session.js",
            "start": {"line": 28, "col": 5},
            "end": {"line": 32, "col": 7},
            "message": "Cookie missing HttpOnly flag",
            "severity": "WARNING",
            "extra": {
                "message": "Session cookie does not have HttpOnly flag set"
            }
        }
    ]
    
    sample_scan_results = {
        "semgrep": {
            "status": "completed",
            "findings": 3,
            "details": sample_findings
        },
        "gitleaks": {
            "status": "completed", 
            "git_secrets_found": 5,
            "details": [
                {"type": "aws-access-token", "file": "config/aws.js", "line": 12},
                {"type": "api-key", "file": ".env.backup", "line": 7},
                {"type": "private-key", "file": "keys/private.pem", "line": 1}
            ]
        },
        "detect_secrets": {
            "status": "completed",
            "credentials_found": 8,
            "files_with_secrets": 4
        }
    }
    
    print("📊 Sample Security Scan Results:")
    print(f"   • Security Issues Found: {len(sample_findings)}")
    print(f"   • Git Secrets Detected: 5")
    print(f"   • Credential Files: 4")
    print(f"   • Total Risk Items: 13")
    print()
    
    print("🧠 Generating AI Analysis...")
    print("   Using Claude 3.5 Sonnet for intelligent security insights...")
    print()
    
    try:
        ai_insights = await generate_ai_security_insights(
            scan_results=sample_scan_results,
            all_findings=sample_findings,
            repository_url="https://github.com/example/mobile-banking-app",
            total_issues=len(sample_findings),
            total_secrets=13
        )
        
        print("✅ AI Analysis Complete!")
        print("=" * 50)
        
        # Display key insights
        if "error" in ai_insights:
            print(f"❌ AI Analysis Error: {ai_insights['error']}")
            return
        
        print("📋 EXECUTIVE SUMMARY:")
        if "executive_summary" in ai_insights:
            print(f"   {ai_insights['executive_summary']}")
        print()
        
        print("🚨 CRITICAL ISSUES:")
        if "critical_issues" in ai_insights:
            for i, issue in enumerate(ai_insights["critical_issues"][:3], 1):
                print(f"   {i}. {issue.get('title', 'Critical Security Issue')}")
                print(f"      Impact: {issue.get('impact', 'High risk to application security')}")
                print(f"      Fix: {issue.get('fix', 'Immediate remediation required')}")
                print()
        
        print("📱 MOBILE-SPECIFIC RISKS:")
        if "mobile_risks" in ai_insights:
            for risk in ai_insights["mobile_risks"][:3]:
                print(f"   • {risk}")
        print()
        
        print("🔑 SECRETS ANALYSIS:")
        if "secrets_analysis" in ai_insights:
            print(f"   {ai_insights['secrets_analysis']}")
        print()
        
        print("⚡ OVERALL RISK SCORE:")
        if "overall_risk_score" in ai_insights:
            score = ai_insights["overall_risk_score"]
            risk_level = "LOW" if score <= 3 else "MEDIUM" if score <= 6 else "HIGH" if score <= 8 else "CRITICAL"
            print(f"   Score: {score}/10 ({risk_level} RISK)")
        print()
        
        print("🛠️  NEXT STEPS:")
        if "next_steps" in ai_insights:
            for i, step in enumerate(ai_insights["next_steps"][:3], 1):
                print(f"   {i}. {step}")
        print()
        
        # Save full report
        report_file = "ai_security_analysis_demo.json"
        with open(report_file, 'w') as f:
            json.dump(ai_insights, f, indent=2)
        
        print(f"📄 Full AI analysis report saved to: {report_file}")
        print()
        print("🎉 Demo completed successfully!")
        print("This demonstrates how Claude AI can transform raw security findings")
        print("into actionable business intelligence and technical guidance.")
        
    except Exception as e:
        print(f"❌ AI Analysis Failed: {str(e)}")
        print()
        print("Possible issues:")
        print("• Invalid Anthropic API key")
        print("• Network connectivity problems") 
        print("• API rate limits exceeded")
        print("• Service temporarily unavailable")

if __name__ == "__main__":
    # Load environment variables
    from dotenv import load_dotenv
    load_dotenv()
    
    # Run the demo
    asyncio.run(demo_ai_analysis())