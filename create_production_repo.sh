#!/bin/bash

# Create production-grade repository structure for codebase scanner

echo "🚀 Creating production-grade codebase scanner repository structure..."

# Create main directories
mkdir -p codebase_scanner/{frontend,backend,docs,scripts,.github/workflows}

# Frontend structure
mkdir -p codebase_scanner/frontend/{src/{components,pages,services,hooks,utils,types},public,tests}
mkdir -p codebase_scanner/frontend/src/components/{ui,layout,forms,scanner}

# Backend structure  
mkdir -p codebase_scanner/backend/{app/{api,models,services,utils},tests,migrations}
mkdir -p codebase_scanner/backend/app/api/{auth,projects,scans,reports}

# Create essential files
echo "Creating essential configuration files..."

# Root package.json for workspace
cat > codebase_scanner/package.json << 'EOF'
{
  "name": "codebase-scanner",
  "version": "1.0.0",
  "description": "Production-grade security scanner for codebases",
  "workspaces": ["frontend", "backend"],
  "scripts": {
    "dev": "concurrently \"npm run dev:frontend\" \"npm run dev:backend\"",
    "dev:frontend": "cd frontend && npm run dev",
    "dev:backend": "cd backend && uvicorn app.main:app --reload",
    "build": "npm run build:frontend",
    "build:frontend": "cd frontend && npm run build",
    "test": "npm run test:frontend && npm run test:backend",
    "test:frontend": "cd frontend && npm test",
    "test:backend": "cd backend && pytest"
  },
  "devDependencies": {
    "concurrently": "^8.2.2"
  }
}
EOF

# Frontend package.json
cat > codebase_scanner/frontend/package.json << 'EOF'
{
  "name": "codebase-scanner-frontend",
  "version": "1.0.0",
  "type": "module",
  "scripts": {
    "dev": "vite",
    "build": "tsc && vite build",
    "preview": "vite preview",
    "test": "vitest",
    "lint": "eslint . --ext ts,tsx --report-unused-disable-directives --max-warnings 0"
  },
  "dependencies": {
    "@supabase/supabase-js": "^2.38.0",
    "@tanstack/react-query": "^5.8.0",
    "@headlessui/react": "^1.7.17",
    "@heroicons/react": "^2.0.18",
    "react": "^18.2.0",
    "react-dom": "^18.2.0",
    "react-router-dom": "^6.17.0",
    "react-hook-form": "^7.47.0",
    "react-hot-toast": "^2.4.1",
    "clsx": "^2.0.0",
    "date-fns": "^2.30.0"
  },
  "devDependencies": {
    "@types/react": "^18.2.33",
    "@types/react-dom": "^18.2.14",
    "@typescript-eslint/eslint-plugin": "^6.10.0",
    "@typescript-eslint/parser": "^6.10.0",
    "@vitejs/plugin-react": "^4.1.0",
    "autoprefixer": "^10.4.16",
    "eslint": "^8.53.0",
    "eslint-plugin-react-hooks": "^4.6.0",
    "eslint-plugin-react-refresh": "^0.4.4",
    "postcss": "^8.4.31",
    "tailwindcss": "^3.3.5",
    "typescript": "^5.2.2",
    "vite": "^4.5.0",
    "vitest": "^0.34.6"
  }
}
EOF

# Backend requirements
cat > codebase_scanner/backend/requirements.txt << 'EOF'
fastapi==0.104.1
uvicorn[standard]==0.24.0
supabase==2.0.2
pydantic==2.4.2
pydantic-settings==2.0.3
python-multipart==0.0.6
python-jose[cryptography]==3.3.0
passlib[bcrypt]==1.7.4
celery==5.3.4
redis==5.0.1
pytest==7.4.3
pytest-asyncio==0.21.1
httpx==0.25.1
aiofiles==23.2.1
python-dotenv==1.0.0
asyncpg==0.29.0
sqlalchemy[asyncio]==2.0.23
alembic==1.12.1
semgrep==1.45.0
bandit==1.7.5
safety==2.3.5
GitPython==3.1.40
EOF

# Docker setup
cat > codebase_scanner/docker-compose.yml << 'EOF'
version: '3.8'

services:
  frontend:
    build:
      context: ./frontend
      dockerfile: Dockerfile
    ports:
      - "5173:5173"
    environment:
      - VITE_SUPABASE_URL=${VITE_SUPABASE_URL}
      - VITE_SUPABASE_ANON_KEY=${VITE_SUPABASE_ANON_KEY}
    volumes:
      - ./frontend:/app
      - /app/node_modules
    depends_on:
      - backend

  backend:
    build:
      context: ./backend
      dockerfile: Dockerfile
    ports:
      - "8000:8000"
    environment:
      - SUPABASE_URL=${SUPABASE_URL}
      - SUPABASE_SERVICE_KEY=${SUPABASE_SERVICE_KEY}
      - REDIS_URL=${REDIS_URL}
    volumes:
      - ./backend:/app
      - /app/__pycache__
    depends_on:
      - redis

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    command: redis-server --appendonly yes
    volumes:
      - redis_data:/data

  celery:
    build:
      context: ./backend
      dockerfile: Dockerfile
    command: celery -A app.celery_app worker --loglevel=info
    environment:
      - SUPABASE_URL=${SUPABASE_URL}
      - SUPABASE_SERVICE_KEY=${SUPABASE_SERVICE_KEY}
      - REDIS_URL=${REDIS_URL}
    volumes:
      - ./backend:/app
    depends_on:
      - redis

volumes:
  redis_data:
EOF

# Environment template
cat > codebase_scanner/.env.example << 'EOF'
# Supabase Configuration
SUPABASE_URL=your_supabase_project_url
SUPABASE_ANON_KEY=your_supabase_anon_key
SUPABASE_SERVICE_KEY=your_supabase_service_key

# Frontend Environment Variables
VITE_SUPABASE_URL=${SUPABASE_URL}
VITE_SUPABASE_ANON_KEY=${SUPABASE_ANON_KEY}
VITE_API_URL=http://localhost:8000

# Backend Environment Variables
REDIS_URL=redis://localhost:6379
SECRET_KEY=your_super_secret_key_here
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30

# Development
NODE_ENV=development
PYTHON_ENV=development
EOF

# README
cat > codebase_scanner/README.md << 'EOF'
# Codebase Scanner

A production-grade security scanner for analyzing codebases and detecting vulnerabilities.

## Features

- 🔍 **Static Code Analysis**: Detect security vulnerabilities, code quality issues
- 📦 **Dependency Scanning**: Identify vulnerable dependencies and outdated packages  
- 🛡️ **OWASP Integration**: Follow OWASP Top 10 and industry security standards
- 📊 **Professional Reporting**: CVSS scoring, compliance mappings, risk assessment
- 🔐 **Enterprise Auth**: Supabase authentication with role-based access
- 🚀 **Scalable Architecture**: Built for production with Docker and microservices

## Tech Stack

### Frontend
- React 18 + TypeScript
- Vite for development and building
- Tailwind CSS for styling
- TanStack Query for API state management
- Supabase JS for authentication and real-time data

### Backend  
- FastAPI with Python 3.11+
- Supabase for database, auth, and storage
- Celery + Redis for background job processing
- Docker for containerization
- Comprehensive security scanning tools

## Quick Start

### Prerequisites
- Node.js 18+
- Python 3.11+
- Docker & Docker Compose
- Supabase account

### 1. Clone Repository
```bash
git clone https://github.com/BitCodeHub/codebase_scanner.git
cd codebase_scanner
```

### 2. Environment Setup
```bash
cp .env.example .env
# Edit .env with your Supabase credentials
```

### 3. Install Dependencies
```bash
# Install all dependencies
npm install

# Or install separately
cd frontend && npm install
cd ../backend && pip install -r requirements.txt
```

### 4. Start Development Environment
```bash
# Start all services with Docker
docker-compose up -d

# Or start manually
npm run dev
```

### 5. Setup Database
```bash
# Run Supabase migrations
cd backend && python scripts/setup_database.py
```

## Supabase Setup

1. Create account at [supabase.com](https://supabase.com)
2. Create new project
3. Get your project URL and API keys
4. Update `.env` file with credentials
5. Run database migrations

## Deployment

### Frontend (Vercel)
```bash
npm run build:frontend
# Deploy to Vercel
```

### Backend (Railway/Render)
```bash
# Deploy to Railway or Render
# Configure environment variables
```

## API Documentation

Once running, visit:
- Frontend: http://localhost:5173
- Backend API: http://localhost:8000
- API Docs: http://localhost:8000/docs

## Contributing

1. Fork the repository
2. Create feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
EOF

# GitHub workflow
mkdir -p codebase_scanner/.github/workflows
cat > codebase_scanner/.github/workflows/ci.yml << 'EOF'
name: CI/CD Pipeline

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
  test-frontend:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v4
    - name: Setup Node.js
      uses: actions/setup-node@v3
      with:
        node-version: '18'
        cache: 'npm'
        cache-dependency-path: frontend/package-lock.json
    
    - name: Install dependencies
      run: cd frontend && npm ci
    
    - name: Run tests
      run: cd frontend && npm test
    
    - name: Build
      run: cd frontend && npm run build

  test-backend:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v4
    - name: Setup Python
      uses: actions/setup-python@v4
      with:
        python-version: '3.11'
    
    - name: Install dependencies
      run: |
        cd backend
        pip install -r requirements.txt
    
    - name: Run tests
      run: cd backend && pytest
    
    - name: Security scan
      run: cd backend && bandit -r app/

  deploy-staging:
    needs: [test-frontend, test-backend]
    runs-on: ubuntu-latest
    if: github.ref == 'refs/heads/develop'
    steps:
    - name: Deploy to staging
      run: echo "Deploy to staging environment"

  deploy-production:
    needs: [test-frontend, test-backend]
    runs-on: ubuntu-latest
    if: github.ref == 'refs/heads/main'
    steps:
    - name: Deploy to production
      run: echo "Deploy to production environment"
EOF

echo "✅ Repository structure created successfully!"
echo ""
echo "📁 Directory structure:"
find codebase_scanner -type d | head -20

echo ""
echo "🚀 Next steps:"
echo "1. cd codebase_scanner"
echo "2. Initialize git repository: git init"
echo "3. Add remote: git remote add origin https://github.com/BitCodeHub/codebase_scanner.git"
echo "4. Create .env file from .env.example"
echo "5. Set up Supabase project"
echo "6. Install dependencies: npm install"
echo "7. Start development: npm run dev"