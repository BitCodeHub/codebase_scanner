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
