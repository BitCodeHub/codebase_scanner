# Anthropic API Key Setup Guide

## Current Status ✅
Your Anthropic API key is **properly configured** in Render, but the account has **insufficient credits**.

## Error Message
```
Your credit balance is too low to access the Anthropic API. 
Please go to Plans & Billing to upgrade or purchase credits.
```

## How to Fix This

### Option 1: Add Credits to Your Anthropic Account
1. Go to [Anthropic Console](https://console.anthropic.com/)
2. Navigate to "Plans & Billing"
3. Add credits to your account
4. The AI analysis will start working immediately (no redeployment needed)

### Option 2: Use a Different API Key
If you have another Anthropic account with credits:

1. **Get your API key** from [Anthropic Console](https://console.anthropic.com/account/keys)
   - API keys start with `sk-ant-`

2. **Update in Render Dashboard**:
   - Go to your [Render Dashboard](https://dashboard.render.com/)
   - Click on your backend service: `codebase-scanner-backend-docker`
   - Click "Environment" in the left sidebar
   - Find or add `ANTHROPIC_API_KEY`
   - Update the value with your new API key
   - Click "Save Changes"
   - Service will automatically redeploy

## Testing Your API Key

After adding credits or updating the key, test it with:

```bash
# Quick test
curl -X POST https://codebase-scanner-backend-docker.onrender.com/api/test/ai-analysis

# Or use the test script
python3 test_anthropic_key.py
```

## What the AI Analysis Provides

When working with sufficient credits, the AI analysis will provide:

- **Executive Summary** - High-level security assessment
- **Critical Issues** - Top 3 most dangerous vulnerabilities
- **Risk Assessment** - Overall security risk score and business impact
- **Remediation Steps** - Specific fixes for each vulnerability
- **Compliance Mapping** - How findings relate to OWASP, PCI-DSS, etc.
- **Prevention Strategies** - Long-term security improvements

## Alternative: Run Without AI Analysis

The scanner works perfectly without AI analysis. You'll still get:
- All 10 security tools scanning
- Detailed vulnerability reports
- SARIF format results
- Severity classifications

The AI analysis is an optional enhancement that provides business-friendly explanations and prioritization.

## Environment Variables in Render

Your current environment variables:
- ✅ `PYTHON_ENV=production` 
- ✅ `ANTHROPIC_API_KEY` (configured but needs credits)
- ✅ `SUPABASE_URL`
- ✅ `SUPABASE_ANON_KEY`
- ✅ Other required variables

## Support

If you need help:
1. Check your Anthropic account credits
2. Verify the API key starts with `sk-ant-`
3. Use the test script to diagnose issues
4. Check Render logs for any errors