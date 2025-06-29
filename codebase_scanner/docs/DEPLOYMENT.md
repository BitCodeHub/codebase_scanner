# Production Deployment Guide

## 🚀 Deployment Options

### Option 1: Vercel + Railway (Recommended)

**Frontend: Vercel**
- ✅ Free tier available
- ✅ Automatic HTTPS
- ✅ Global CDN
- ✅ Preview deployments

**Backend: Railway**
- ✅ Simple Docker deployment
- ✅ Automatic scaling
- ✅ Built-in monitoring
- ✅ Environment management

### Option 2: Netlify + Render

**Frontend: Netlify**
- ✅ Free tier available
- ✅ Form handling
- ✅ Split testing

**Backend: Render**
- ✅ Docker support
- ✅ Auto-scaling
- ✅ Health checks

### Option 3: Docker + VPS

**Self-hosted with Docker Compose**
- ✅ Full control
- ✅ Cost-effective for high traffic
- ⚠️ Requires server management

---

## 🔧 Frontend Deployment (Vercel)

### 1. Prepare Repository
```bash
# Ensure your code is pushed to GitHub
git add .
git commit -m "Production ready"
git push origin main
```

### 2. Deploy to Vercel
1. **Visit [vercel.com](https://vercel.com)**
2. **Connect GitHub account**
3. **Import your repository**
4. **Configure build settings**:
   - Framework Preset: `Vite`
   - Root Directory: `frontend`
   - Build Command: `npm run build`
   - Output Directory: `dist`

### 3. Environment Variables
Add these in Vercel dashboard:
```
VITE_SUPABASE_URL=your_supabase_url
VITE_SUPABASE_ANON_KEY=your_supabase_anon_key
VITE_API_URL=your_backend_url
```

### 4. Custom Domain (Optional)
1. **Go to Domains tab in Vercel**
2. **Add your domain**
3. **Configure DNS records**

---

## 🔧 Backend Deployment (Railway)

### 1. Prepare Railway Account
1. **Visit [railway.app](https://railway.app)**
2. **Sign up with GitHub**
3. **Create new project**

### 2. Deploy Backend
1. **Connect GitHub repository**
2. **Select backend directory**
3. **Railway auto-detects Dockerfile**
4. **Configure environment variables**

### 3. Environment Variables
```bash
# Required
SUPABASE_URL=your_supabase_url
SUPABASE_SERVICE_KEY=your_supabase_service_key
SUPABASE_ANON_KEY=your_supabase_anon_key
SECRET_KEY=your_super_secret_key
REDIS_URL=redis://redis:6379

# Optional
PYTHON_ENV=production
DEBUG=false
MAX_FILE_SIZE=104857600
FRONTEND_URL=https://your-frontend-domain.vercel.app
```

### 4. Redis Setup
1. **Add Redis service in Railway**
2. **Connect to backend service**
3. **Update REDIS_URL environment variable**

### 5. Custom Domain (Optional)
1. **Go to Settings → Domains**
2. **Add custom domain**
3. **Configure DNS**

---

## 🗄️ Database Migration

### Supabase Production Setup
1. **Create production Supabase project**
2. **Run SQL schema from `docs/SUPABASE_SETUP.md`**
3. **Configure production environment variables**
4. **Test database connection**

### Data Migration (if needed)
```bash
# Export from development
supabase db dump --db-url "postgresql://dev-connection"

# Import to production
supabase db reset --db-url "postgresql://prod-connection"
```

---

## 🔒 Security Configuration

### 1. Environment Security
- ✅ Never commit `.env` files
- ✅ Use different keys for each environment
- ✅ Rotate secrets regularly
- ✅ Use strong, random secret keys

### 2. CORS Configuration
Update backend CORS settings:
```python
# app/main.py
ALLOWED_ORIGINS = [
    "https://your-domain.vercel.app",
    "https://your-custom-domain.com"
]
```

### 3. Supabase Security
- ✅ Enable Row Level Security
- ✅ Configure storage policies
- ✅ Set up API rate limiting
- ✅ Enable 2FA on Supabase account

---

## 📊 Monitoring & Analytics

### 1. Application Monitoring
```python
# Add to requirements.txt
sentry-sdk[fastapi]==1.32.0

# app/main.py
import sentry_sdk
from sentry_sdk.integrations.fastapi import FastApiIntegration

sentry_sdk.init(
    dsn="your-sentry-dsn",
    integrations=[FastApiIntegration()],
    traces_sample_rate=1.0,
)
```

### 2. Performance Monitoring
- **Vercel Analytics**: Built-in performance monitoring
- **Railway Metrics**: CPU, memory, and request metrics
- **Supabase Dashboard**: Database performance

### 3. Error Tracking
- **Sentry**: Error tracking and performance monitoring
- **LogRocket**: Frontend session replay
- **Railway Logs**: Server logs and debugging

---

## 🔄 CI/CD Pipeline

### GitHub Actions Workflow
```yaml
# .github/workflows/deploy.yml
name: Deploy to Production

on:
  push:
    branches: [main]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Setup Node.js
        uses: actions/setup-node@v3
        with:
          node-version: '18'
      - name: Run frontend tests
        run: |
          cd frontend
          npm ci
          npm test
      - name: Run backend tests
        run: |
          cd backend
          pip install -r requirements.txt
          pytest

  deploy-frontend:
    needs: test
    runs-on: ubuntu-latest
    steps:
      - name: Deploy to Vercel
        uses: amondnet/vercel-action@v25
        with:
          vercel-token: ${{ secrets.VERCEL_TOKEN }}
          vercel-org-id: ${{ secrets.ORG_ID }}
          vercel-project-id: ${{ secrets.PROJECT_ID }}

  deploy-backend:
    needs: test
    runs-on: ubuntu-latest
    steps:
      - name: Deploy to Railway
        uses: railway-deploy@v1
        with:
          railway-token: ${{ secrets.RAILWAY_TOKEN }}
```

---

## 🏃‍♂️ Quick Deployment Checklist

### Pre-deployment
- [ ] Code is committed and pushed
- [ ] Tests are passing
- [ ] Environment variables are configured
- [ ] Supabase database is set up
- [ ] Security policies are in place

### Frontend Deployment
- [ ] Vercel project created
- [ ] Repository connected
- [ ] Environment variables added
- [ ] Build successful
- [ ] Custom domain configured (optional)

### Backend Deployment
- [ ] Railway project created
- [ ] Docker image builds successfully
- [ ] Environment variables configured
- [ ] Redis service connected
- [ ] Health checks passing

### Post-deployment
- [ ] Frontend loads correctly
- [ ] API endpoints respond
- [ ] Authentication works
- [ ] File uploads work
- [ ] Scans execute successfully
- [ ] Error monitoring configured

---

## 🆘 Troubleshooting

### Common Issues

**1. Build Failures**
```bash
# Check logs in deployment platform
# Verify Node.js/Python versions
# Check dependency installation
```

**2. Environment Variable Issues**
```bash
# Verify all required variables are set
# Check variable names and values
# Restart services after changes
```

**3. Database Connection Issues**
```bash
# Verify Supabase URL and keys
# Check RLS policies
# Test connection from backend
```

**4. CORS Errors**
```bash
# Update allowed origins in backend
# Check frontend API URL configuration
# Verify protocol (http vs https)
```

### Getting Help
- 📧 Check deployment platform documentation
- 💬 Join Discord/Slack communities
- 🐛 Create GitHub issues
- 📚 Review application logs

---

## 💰 Cost Optimization

### Free Tier Limits
- **Vercel**: 100GB bandwidth/month
- **Railway**: $5 credit, then pay-as-you-go
- **Supabase**: 500MB database, 1GB storage
- **Redis**: Various free options available

### Scaling Considerations
- Monitor usage in dashboards
- Optimize database queries
- Implement caching
- Consider CDN for static assets
- Use background jobs for heavy processing

### Cost Monitoring
- Set up billing alerts
- Monitor resource usage
- Optimize expensive operations
- Consider reserved instances for high usage