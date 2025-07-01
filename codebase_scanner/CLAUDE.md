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

### Installed and Configured Tools (10 total):

#### Core Security Tools:
- **Semgrep v1.127.1** - Static analysis with mobile-specific rules
- **Bandit v1.8.5** - Python security linter
- **Safety v3.5.2** - Dependency vulnerability scanner
- **Gitleaks v8.27.2** - Git secrets scanner

#### Mobile-Specific Security Tools:
- **TruffleHog v2.2.1** - Deep secrets detection in repositories
- **detect-secrets v1.5.0** - Advanced credential scanning
- **Retire.js v5.2.7** - JavaScript vulnerability scanner
- **JADX v1.5.2** - Android APK analysis and decompilation
- **APKLeaks v2.6.3** - Android app secrets detection
- **QARK v4.0.0** - Android security assessment

### Security Scanning Capabilities:
- **Client ID and API Key Detection**: Comprehensive scanning for hardcoded credentials
- **Mobile App Vulnerabilities**: OWASP Mobile Top 10 compliance checking
- **Git History Secrets**: Deep scanning of commit history for leaked credentials
- **JavaScript/React Native Security**: Vulnerability detection in JS frameworks
- **Android APK Analysis**: Static analysis of compiled Android applications
- **Production App Scanning**: Real-time security assessment of live codebases

### API Endpoints:
- `/api/test/scanner-tools` - Test all 10 security tools availability
- `/api/scans/mobile-app` - Comprehensive mobile app security scanning
- `/api/scans/repository-simple` - General repository security scanning

### Usage Example:
```bash
curl -X POST "http://localhost:8000/api/scans/mobile-app" \
  -H "Content-Type: application/json" \
  -d '{
    "project_id": "1",
    "repository_url": "https://github.com/your-org/mobile-app",
    "branch": "main",
    "scan_type": "comprehensive",
    "user_id": "user-id"
  }'
```

### Security Focus Areas:
1. Hardcoded API keys, client IDs, and secrets
2. Mobile-specific vulnerabilities (OWASP Mobile Top 10)
3. JavaScript/React Native security issues
4. Git commit history credential leaks
5. Android APK security analysis
6. Production codebase security assessment

## Key Files
- Backend project API: `/backend/src/api/projects.py`
- Frontend project service: `/frontend/src/services/projectService.ts`
- Database schema: `/supabase_schema.sql`
- API configuration: `/frontend/src/utils/api-config.ts`
- Mobile security endpoint: `/backend/app/main.py` (lines 528-716)