#!/usr/bin/env python3
"""Test Anthropic API key configuration"""

import requests
import json
import sys

BACKEND_URL = "https://codebase-scanner-backend-docker.onrender.com"

def test_ai_analysis():
    """Test if AI analysis is working with the configured API key"""
    
    print("Testing Anthropic API Key Configuration...")
    print("=" * 50)
    
    # Test the AI analysis endpoint
    try:
        response = requests.post(
            f"{BACKEND_URL}/api/test/ai-analysis",
            timeout=30
        )
        
        print(f"Status Code: {response.status_code}")
        
        if response.status_code == 200:
            data = response.json()
            
            # Check for AI insights error
            ai_insights = data.get('ai_insights', {})
            if 'error' in ai_insights:
                error_msg = ai_insights['error']
                if 'credit balance is too low' in error_msg:
                    print("\n⚠️  API Key is configured but account has insufficient credits!")
                    print("\nError from Anthropic:")
                    print(error_msg.split("Error code: 400 - ")[-1])
                    return "insufficient_credits"
                else:
                    print(f"\n❌ AI Analysis Error: {error_msg}")
                    return False
            
            print("\n✅ AI Analysis is working!")
            print(f"\nAnalysis Type: {data.get('analysis_type', 'Unknown')}")
            
            # Check for Claude response
            ai_analysis = data.get('ai_analysis', {})
            if ai_analysis:
                print("\n🤖 Claude AI Response Received:")
                print(f"- Executive Summary: {'✓' if ai_analysis.get('executive_summary') else '✗'}")
                print(f"- Critical Issues: {'✓' if ai_analysis.get('critical_issues') else '✗'}")
                print(f"- Recommendations: {'✓' if ai_analysis.get('recommendations') else '✗'}")
                print(f"- Risk Assessment: {'✓' if ai_analysis.get('risk_assessment') else '✗'}")
                
                # Show a sample of the executive summary
                if ai_analysis.get('executive_summary'):
                    summary = ai_analysis['executive_summary']
                    print(f"\nExecutive Summary Preview:")
                    print(f"{summary[:200]}..." if len(summary) > 200 else summary)
            
            return True
            
        elif response.status_code == 500:
            # Check if it's an API key error
            try:
                error_data = response.json()
                error_detail = error_data.get('detail', '')
                
                if 'ANTHROPIC_API_KEY' in str(error_detail):
                    print("\n❌ ANTHROPIC_API_KEY is not properly configured!")
                    print("The environment variable is either missing or invalid.")
                else:
                    print(f"\n❌ Server Error: {error_detail}")
            except:
                print(f"\n❌ Server Error: {response.text[:200]}")
            
        else:
            print(f"\n❌ Unexpected status code: {response.status_code}")
            print(f"Response: {response.text[:200]}")
            
    except requests.exceptions.Timeout:
        print("\n⏱️  Request timed out (AI analysis can take up to 30 seconds)")
    except Exception as e:
        print(f"\n❌ Error: {type(e).__name__}: {str(e)}")
        
    return False

def check_env_endpoint():
    """Check if we can see environment info"""
    print("\n\nChecking Environment Configuration...")
    print("=" * 50)
    
    try:
        response = requests.get(f"{BACKEND_URL}/api/test", timeout=5)
        if response.status_code == 200:
            data = response.json()
            env = data.get('environment', 'Unknown')
            print(f"Environment: {env}")
            
            # Check if Supabase is configured (as a proxy for env vars working)
            if data.get('supabase_configured'):
                print("✅ Environment variables are being read properly")
            else:
                print("⚠️  Some environment variables may not be configured")
                
    except Exception as e:
        print(f"Error checking environment: {e}")

if __name__ == "__main__":
    # First check environment
    check_env_endpoint()
    
    # Then test AI analysis
    print("\n")
    result = test_ai_analysis()
    
    if result == "insufficient_credits":
        print("\n💳 To fix the insufficient credits issue:")
        print("1. Go to https://console.anthropic.com/")
        print("2. Navigate to 'Plans & Billing'")
        print("3. Add credits to your account")
        print("4. The AI analysis will start working immediately")
        print("\n✅ Your API key is properly configured in Render!")
        print("   You just need to add credits to your Anthropic account.")
    elif not result:
        print("\n📝 To fix this issue in Render:")
        print("1. Go to your Render dashboard")
        print("2. Navigate to your backend service")
        print("3. Click on 'Environment' in the left sidebar")
        print("4. Add or update the environment variable:")
        print("   - Key: ANTHROPIC_API_KEY")
        print("   - Value: Your Anthropic API key (starts with 'sk-ant-')")
        print("5. Click 'Save Changes'")
        print("6. The service will automatically redeploy")
        
    sys.exit(0 if result else 1)