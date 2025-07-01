# Production Deployment Guide

## 🚀 Deployment on Render

### Frontend Deployment
- **URL**: https://codebase-scanner-frontend.onrender.com
- **Service Type**: Static Site
- **Build Command**: `npm run build`
- **Publish Directory**: `dist`
- **Environment Variables**:
  ```
  VITE_SUPABASE_URL=https://ylllkgxzrizqlsymkybh.supabase.co
  VITE_SUPABASE_ANON_KEY=your-anon-key
  VITE_API_URL=https://codebase-scanner-backend.onrender.com
  ```

### Backend Deployment
- **URL**: https://codebase-scanner-backend.onrender.com
- **Service Type**: Web Service
- **Runtime**: Python 3.11
- **Build Command**: `pip install -r requirements.txt`
- **Start Command**: `uvicorn app.main:app --host 0.0.0.0 --port $PORT`
- **Environment Variables**:
  ```
  SUPABASE_URL=https://ylllkgxzrizqlsymkybh.supabase.co
  SUPABASE_SERVICE_ROLE_KEY=your-service-role-key
  ANTHROPIC_API_KEY=your-anthropic-api-key
  CORS_ORIGINS=https://codebase-scanner-frontend.onrender.com
  PYTHON_ENV=production
  ```

## 🔧 Configuration Updates for Production

### 1. Frontend Configuration
- ✅ `src/generated/config.ts` - Updated to use production API URL
- ✅ `src/generated/config.json` - Updated to use production API URL
- ✅ `src/utils/api-config.ts` - Already configured with production detection
- ✅ `src/services/scanService.ts` - Re-enabled authentication

### 2. Backend Configuration
- ✅ `app/main.py` - Added production frontend URL to CORS origins
- ✅ `.env.example` - Includes production CORS configuration

## 🛡️ Security Tools Available
All 10 security tools are installed and operational:
1. Semgrep v1.127.1
2. Bandit v1.8.5
3. Safety v3.5.2
4. Gitleaks v8.27.2
5. TruffleHog v2.2.1
6. detect-secrets v1.5.0
7. Retire.js v5.2.7
8. JADX v1.5.2
9. APKLeaks v2.6.3
10. QARK v4.0.0

## 🤖 Claude AI Integration
- **Status**: Technically integrated and working
- **Requirement**: Add credits to Anthropic account for production use
- **Features**: 
  - Executive summaries
  - Vulnerability explanations
  - Fix recommendations
  - Compliance mapping
  - Risk prioritization

## 📋 Pre-Deployment Checklist
- [ ] Set all environment variables on Render
- [ ] Ensure Supabase credentials are correct
- [ ] Add Anthropic API key with credits
- [ ] Update CORS_ORIGINS if custom domain is used
- [ ] Test authentication flow
- [ ] Verify security tools are accessible

## 🔄 Deployment Commands
```bash
# Frontend
cd frontend
npm run build

# Backend
cd backend
pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

## 🌐 Production URLs
- **Frontend**: https://codebase-scanner-frontend.onrender.com
- **Backend API**: https://codebase-scanner-backend.onrender.com
- **API Docs**: https://codebase-scanner-backend.onrender.com/docs