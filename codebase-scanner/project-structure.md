# Codebase Scanner Project Structure

```
codebase-scanner/
├── backend/
│   ├── app/
│   │   ├── __init__.py
│   │   ├── main.py              # FastAPI app entry point
│   │   ├── config.py            # Configuration management
│   │   ├── api/
│   │   │   ├── __init__.py
│   │   │   ├── auth.py          # Authentication endpoints
│   │   │   ├── projects.py      # Project management endpoints
│   │   │   ├── scans.py         # Scan endpoints
│   │   │   └── reports.py       # Report endpoints
│   │   ├── models/
│   │   │   ├── __init__.py
│   │   │   ├── user.py          # User model
│   │   │   ├── project.py       # Project model
│   │   │   ├── scan.py          # Scan model
│   │   │   └── report.py        # Report model
│   │   ├── services/
│   │   │   ├── __init__.py
│   │   │   ├── github.py        # GitHub integration
│   │   │   ├── scanner.py       # Scanning engine
│   │   │   ├── ai_analyzer.py   # AI vulnerability detection
│   │   │   └── queue.py         # Job queue management
│   │   ├── analyzers/
│   │   │   ├── __init__.py
│   │   │   ├── python.py        # Python analyzer
│   │   │   ├── javascript.py    # JavaScript analyzer
│   │   │   ├── java.py          # Java analyzer
│   │   │   └── base.py          # Base analyzer class
│   │   └── utils/
│   │       ├── __init__.py
│   │       ├── security.py      # Security utilities
│   │       └── database.py      # Database utilities
│   ├── tests/
│   ├── requirements.txt
│   └── Dockerfile
├── frontend/
│   ├── src/
│   │   ├── components/
│   │   │   ├── Dashboard.jsx
│   │   │   ├── ProjectList.jsx
│   │   │   ├── ScanResults.jsx
│   │   │   └── Report.jsx
│   │   ├── services/
│   │   │   ├── api.js
│   │   │   └── auth.js
│   │   ├── App.jsx
│   │   └── main.jsx
│   ├── package.json
│   ├── vite.config.js
│   └── Dockerfile
├── docker/
│   ├── scanner/
│   │   └── Dockerfile
│   └── nginx/
│       └── nginx.conf
├── infrastructure/
│   ├── terraform/
│   └── kubernetes/
├── docker-compose.yml
├── .env.example
└── README.md
```