# Codebase Scanner - Security Analysis Platform

A comprehensive web application for scanning GitHub repositories and codebases to provide security analysis, vulnerability detection, and compliance reporting with an intuitive dashboard interface.

## Features

- **Multi-Language Support**: Analyze Python, JavaScript/TypeScript, Java, C/C++, C#, Ruby, Go, PHP, and more
- **Security Scanning**: Static analysis (SAST) with plans for dynamic analysis (DAST)
- **AI-Powered Detection**: Leverage OpenAI/Claude for advanced vulnerability detection
- **GitHub Integration**: OAuth authentication and direct repository scanning
- **Comprehensive Reports**: Security, compliance (OWASP Top 10, CWE/SANS Top 25), and executive reports
- **LaunchReady Badge**: Certification for production-ready code
- **Real-time Dashboard**: Visual analytics and scan progress tracking
- **CI/CD Integration**: Webhook support and automated scanning

## Architecture

```
├── Backend (FastAPI)
│   ├── Authentication & Authorization
│   ├── Project Management
│   ├── Scanning Engine
│   ├── AI Analysis Service
│   └── Report Generation
├── Frontend (React + Tailwind)
│   ├── Dashboard
│   ├── Project Management
│   ├── Scan Results Viewer
│   └── Report Visualization
├── Infrastructure
│   ├── PostgreSQL Database
│   ├── Redis Cache/Queue
│   ├── Docker Containers
│   └── Celery Workers
```

## Quick Start

### Prerequisites

- Docker and Docker Compose
- Python 3.11+
- Node.js 18+
- PostgreSQL 15+
- Redis 7+

### Setup

1. Clone the repository:
```bash
git clone <repository-url>
cd codebase-scanner
```

2. Copy environment variables:
```bash
cp .env.example .env
# Edit .env with your configuration
```

3. Start services with Docker Compose:
```bash
docker-compose up -d
```

4. Access the application:
- Frontend: http://localhost:5173
- Backend API: http://localhost:8000
- API Documentation: http://localhost:8000/docs

### Manual Setup (Development)

#### Backend Setup
```bash
cd backend
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

#### Frontend Setup
```bash
cd frontend
npm install
npm run dev
```

## Configuration

### Required Environment Variables

```env
# Authentication
SECRET_KEY=your-secret-key
JWT_SECRET_KEY=your-jwt-secret

# Database
DATABASE_URL=postgresql://user:password@localhost:5432/codebase_scanner

# GitHub OAuth
GITHUB_CLIENT_ID=your-github-client-id
GITHUB_CLIENT_SECRET=your-github-client-secret

# AI Services (optional)
OPENAI_API_KEY=your-openai-key
ANTHROPIC_API_KEY=your-claude-key

# AWS (optional)
AWS_ACCESS_KEY_ID=your-aws-key
AWS_SECRET_ACCESS_KEY=your-aws-secret
S3_BUCKET_NAME=your-bucket
```

## API Endpoints

### Authentication
- `POST /api/auth/register` - Register new user
- `POST /api/auth/token` - Login
- `GET /api/auth/me` - Get current user
- `GET /api/auth/github/login` - GitHub OAuth

### Projects
- `GET /api/projects` - List projects
- `POST /api/projects` - Create project
- `GET /api/projects/{id}` - Get project details
- `PATCH /api/projects/{id}` - Update project
- `DELETE /api/projects/{id}` - Delete project
- `POST /api/projects/{id}/upload` - Upload code

### Scans
- `POST /api/scans` - Start new scan
- `GET /api/scans` - List scans
- `GET /api/scans/{id}` - Get scan details
- `GET /api/scans/{id}/results` - Get scan results
- `POST /api/scans/{id}/cancel` - Cancel scan

### Reports
- `POST /api/reports` - Generate report
- `GET /api/reports` - List reports
- `GET /api/reports/{id}` - Get report
- `GET /api/reports/{id}/download` - Download report
- `GET /api/reports/{id}/compliance` - Get compliance status

## Security Scanning Tools

The platform integrates multiple security scanning tools:

- **Python**: Bandit, Semgrep
- **JavaScript/TypeScript**: ESLint with security plugins, Semgrep
- **Java**: SpotBugs
- **Go**: Gosec
- **Ruby**: Brakeman
- **PHP**: PHP_CodeSniffer
- **Dependencies**: OWASP Dependency Check
- **Containers**: Trivy

## Development

### Running Tests
```bash
# Backend tests
cd backend
pytest

# Frontend tests
cd frontend
npm test
```

### Adding New Language Support

1. Create analyzer in `backend/app/analyzers/`
2. Extend `BaseAnalyzer` class
3. Implement `analyze()` method
4. Register in `ScannerService`

### Database Migrations
```bash
cd backend
alembic revision --autogenerate -m "Description"
alembic upgrade head
```

## Deployment

### Production Deployment with Docker

```bash
docker-compose -f docker-compose.prod.yml up -d
```

### Kubernetes Deployment

```bash
kubectl apply -f infrastructure/kubernetes/
```

## Security Considerations

- All passwords are hashed using bcrypt
- JWT tokens for authentication
- OAuth tokens encrypted at rest
- Sandboxed scanning environments
- Temporary file storage with automatic cleanup
- Rate limiting on API endpoints

## License

[License information]

## Contributing

1. Fork the repository
2. Create feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open Pull Request

## Support

For issues and feature requests, please use the GitHub issue tracker.