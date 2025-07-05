# Claude Code Assistant Notes

## System Overview
- **Frontend**: React with TypeScript, deployed on Render at https://codebase-scanner-frontend.onrender.com
- **Backend**: FastAPI with Python, deployed on Render at https://codebase-scanner-backend.onrender.com
- **Database**: Supabase PostgreSQL
- **Authentication**: Supabase Auth with JWT tokens

## Important Database Schema Notes
- The `projects` table uses BIGSERIAL for IDs (auto-incrementing bigint), NOT UUIDs
- The `owner_id` field is a UUID that references auth.users
- When querying scans by project_id, convert the string ID to integer: `parseInt(project.id)`

## Common Issues and Solutions

### 1. API URL Configuration
- Production frontend must point to the backend URL, not localhost
- Use `getApiUrl()` from `frontend/src/utils/api-config.ts` for dynamic URL detection

### 2. Dependency Conflicts
- Use flexible version ranges in requirements.txt (e.g., `>=2.7.0,<2.8.0`)
- Let pip resolve complex dependencies instead of pinning exact versions

### 3. Supabase Client Initialization
- May encounter "proxy" parameter errors with certain supabase versions
- Currently using supabase>=2.7.0,<2.8.0 to avoid this issue

### 4. Project Creation Flow
1. Frontend calls projectService.createProject()
2. Backend creates project with auto-generated BIGSERIAL ID
3. Frontend waits 500ms then refreshes project list
4. Projects are displayed with scan counts fetched separately

## Debugging Tips
- Check browser console for API response logs
- Use the "Debug" button on Projects page to test direct API calls
- Use the "Refresh" button to manually reload projects
- Check Render logs for backend errors

## Mobile App Security Scanning Tools

### Installed and Configured Tools (15 total):

#### Core Security Tools (10):
- **Semgrep v1.127.1** - Static analysis with mobile-specific rules
- **Bandit v1.8.5** - Python security linter
- **Safety v3.5.2** - Dependency vulnerability scanner
- **Gitleaks v8.27.2** - Git secrets scanner
- **TruffleHog v2.2.1** - Deep secrets detection in repositories
- **detect-secrets v1.5.0** - Advanced credential scanning
- **Retire.js v5.2.7** - JavaScript vulnerability scanner
- **JADX v1.5.2** - Android APK analysis and decompilation
- **APKLeaks v2.6.3** - Android app secrets detection
- **QARK v4.0.0** - Android security assessment

#### Additional Enterprise Tools (5):
- **ESLint Security** - JavaScript/TypeScript security linting
- **njsscan** - Node.js security scanner
- **Checkov** - Infrastructure as Code security scanner
- **tfsec** - Terraform security scanner
- **OWASP Dependency Check** - Comprehensive dependency vulnerability scanner

### Security Scanning Capabilities:
- **Client ID and API Key Detection**: Comprehensive scanning for hardcoded credentials
- **Mobile App Vulnerabilities**: OWASP Mobile Top 10 compliance checking
- **Git History Secrets**: Deep scanning of commit history for leaked credentials
- **JavaScript/React Native Security**: Vulnerability detection in JS frameworks
- **Android APK Analysis**: Static analysis of compiled Android applications
- **Production App Scanning**: Real-time security assessment of live codebases

### API Endpoints:
- `/api/test/scanner-tools` - Test all 15 security tools availability
- `/api/scans/mobile-app` - Comprehensive mobile app security scanning with AI analysis
- `/api/scans/repository-simple` - General repository security scanning
- `/api/test/ai-analysis` - Test AI security analysis with sample findings
- `/api/ai/analyze-scan-results` - Standalone AI analysis of security scan results

### Usage Examples:

#### Mobile App Security Scan with AI Analysis:
```bash
curl -X POST "http://localhost:8000/api/scans/mobile-app" \
  -H "Content-Type: application/json" \
  -d '{
    "project_id": "1",
    "repository_url": "https://github.com/your-org/mobile-app",
    "branch": "main",
    "scan_type": "comprehensive",
    "user_id": "user-id",
    "enable_ai_analysis": true
  }'
```

#### Test AI Analysis Capabilities:
```bash
curl -X POST "http://localhost:8000/api/test/ai-analysis" \
  -H "Content-Type: application/json"
```

#### Standalone AI Analysis of Scan Results:
```bash
curl -X POST "http://localhost:8000/api/ai/analyze-scan-results" \
  -H "Content-Type: application/json" \
  -d '{
    "scan_results": {
      "semgrep": {"findings": 5, "status": "completed"},
      "gitleaks": {"git_secrets_found": 3, "status": "completed"}
    },
    "findings": [{"check_id": "jwt-hardcoded", "severity": "ERROR"}],
    "repository_url": "https://github.com/example/app"
  }'
```

#### Run AI Analysis Demo:
```bash
cd backend
python3 demo_ai_analysis.py
```

### Security Focus Areas:
1. Hardcoded API keys, client IDs, and secrets
2. Mobile-specific vulnerabilities (OWASP Mobile Top 10)
3. JavaScript/React Native security issues
4. Git commit history credential leaks
5. Android APK security analysis
6. Production codebase security assessment

## AI-Powered Security Analysis

### Claude AI Integration:
- **Intelligent Vulnerability Analysis**: Claude AI analyzes security findings and provides context
- **Plain English Explanations**: Converts technical findings into business-understandable language
- **Fix Recommendations**: Specific, actionable remediation steps for each vulnerability
- **Compliance Mapping**: Maps findings to OWASP, PCI-DSS, SOC 2, and other frameworks
- **Risk Prioritization**: AI-powered risk scoring and prioritization
- **Executive Reporting**: Business-friendly security summaries

### AI Analysis Capabilities:
- **Executive Summary**: High-level risk assessment for business stakeholders
- **Critical Issues**: Top 3 most dangerous vulnerabilities requiring immediate attention
- **Mobile-Specific Risks**: Analysis of mobile app security threats (data leakage, runtime attacks)
- **Secrets Analysis**: Deep analysis of exposed API keys, tokens, and credentials
- **Compliance Violations**: Automatic mapping to security frameworks and standards
- **Remediation Roadmap**: Prioritized action plan with realistic timelines
- **Prevention Strategies**: Long-term security improvement recommendations
- **Developer Education**: Targeted security training recommendations

### AI Configuration:
- **Model**: Claude 3.5 Sonnet (latest)
- **Features**: Real-time analysis, batch processing, contextual insights
- **Environment Variable**: `ANTHROPIC_API_KEY` required for AI features
- **Integration**: Seamlessly integrated with all security scanning tools

## Key Files
- Backend project API: `/backend/src/api/projects.py`
- Frontend project service: `/frontend/src/services/projectService.ts`
- Database schema: `/supabase_schema.sql`
- API configuration: `/frontend/src/utils/api-config.ts`
- Mobile security endpoint: `/backend/app/main.py` (lines 528-716)