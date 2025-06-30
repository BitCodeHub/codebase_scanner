# Testing Guide for Codebase Security Scanner

## Prerequisites Setup

1. **Environment Variables**
   Create a `.env` file in the root directory:
   ```env
   # Supabase
   SUPABASE_URL=your_supabase_url
   SUPABASE_ANON_KEY=your_anon_key
   SUPABASE_SERVICE_KEY=your_service_key
   
   # Claude AI
   ANTHROPIC_API_KEY=your_anthropic_key
   CLAUDE_MODEL=claude-4.0-sonnet
   
   # Security
   SECRET_KEY=your_secret_key_here
   
   # Redis
   REDIS_URL=redis://localhost:6379
   ```

2. **Database Setup**
   ```bash
   cd backend
   python setup_database.py
   ```
   Copy the generated SQL and run it in your Supabase SQL editor.

## Quick Start Testing

### 1. Start All Services
```bash
# Start everything with Docker Compose
docker-compose up -d

# Check all services are running
docker-compose ps
```

Services should be running on:
- Frontend: http://localhost:5173
- Backend API: http://localhost:8000
- API Docs: http://localhost:8000/docs

### 2. Test Authentication
```bash
# Get a demo token
curl -X POST http://localhost:8000/api/auth/demo-token

# Use the token for subsequent requests
export TOKEN="your_token_here"
```

### 3. Test Project Management
```bash
# Create a project
curl -X POST http://localhost:8000/api/projects \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Test Project",
    "description": "Security testing project",
    "language": "python"
  }'

# List projects
curl http://localhost:8000/api/projects \
  -H "Authorization: Bearer $TOKEN"
```

### 4. Test File Upload & Scanning

#### Using the Frontend:
1. Go to http://localhost:5173/dashboard
2. Click "Run Quick Scan"
3. Upload a Python file (or use test files below)
4. Select scan options
5. Start scan and watch real-time progress

#### Using the API:
```bash
# Create a test Python file with vulnerabilities
cat > test_vulnerable.py << 'EOF'
import os
import sqlite3

# SQL Injection vulnerability
def get_user(user_id):
    conn = sqlite3.connect('users.db')
    query = f"SELECT * FROM users WHERE id = {user_id}"  # SQL Injection
    return conn.execute(query).fetchall()

# Hardcoded password
DB_PASSWORD = "admin123"  # Hardcoded credential

# Command injection
def run_command(user_input):
    os.system(f"echo {user_input}")  # Command injection
EOF

# Upload and scan
curl -X POST http://localhost:8000/api/scans \
  -H "Authorization: Bearer $TOKEN" \
  -F "project_id=your_project_id" \
  -F "scan_type=full" \
  -F "file=@test_vulnerable.py"
```

### 5. Test Real-time Progress
Open WebSocket connection to monitor scan progress:
```javascript
// In browser console
const ws = new WebSocket('ws://localhost:8000/ws/scan/YOUR_SCAN_ID');
ws.onmessage = (event) => {
  console.log('Progress:', JSON.parse(event.data));
};
```

### 6. Test AI Analysis
```bash
# Get scan results with AI analysis
curl http://localhost:8000/api/scans/YOUR_SCAN_ID/results \
  -H "Authorization: Bearer $TOKEN"

# Trigger AI analysis for a specific vulnerability
curl -X POST http://localhost:8000/api/ai/analyze-vulnerability \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "vulnerability": {
      "title": "SQL Injection",
      "description": "User input concatenated in SQL query",
      "severity": "critical",
      "code_snippet": "query = f\"SELECT * FROM users WHERE id = {user_id}\""
    }
  }'
```

### 7. Test Export Functionality
```bash
# Export scan report as PDF
curl http://localhost:8000/api/export/scan/YOUR_SCAN_ID?format=pdf \
  -H "Authorization: Bearer $TOKEN" \
  -o security_report.pdf

# Export as Excel
curl http://localhost:8000/api/export/scan/YOUR_SCAN_ID?format=excel \
  -H "Authorization: Bearer $TOKEN" \
  -o security_report.xlsx
```

## Testing Checklist

### Core Features
- [ ] User authentication (login/register)
- [ ] Project creation and management
- [ ] File upload (single and batch)
- [ ] Security scanning execution
- [ ] Real-time progress updates via WebSocket
- [ ] Vulnerability detection (all severity levels)
- [ ] AI-powered analysis with Claude
- [ ] Export reports (PDF, Excel, JSON, CSV)

### Security Tools Integration
- [ ] Semgrep (SAST analysis)
- [ ] Bandit (Python security)
- [ ] Safety (dependency vulnerabilities)
- [ ] GitLeaks (secret detection)

### Production Features
- [ ] Rate limiting (test with multiple requests)
- [ ] Error handling (upload invalid files)
- [ ] Logging (check logs in backend/logs/)
- [ ] File storage in Supabase
- [ ] Background job processing with Celery
- [ ] Redis caching for AI responses

### Performance Testing
```bash
# Test concurrent scans
for i in {1..5}; do
  curl -X POST http://localhost:8000/api/scans \
    -H "Authorization: Bearer $TOKEN" \
    -F "project_id=your_project_id" \
    -F "scan_type=quick" \
    -F "file=@test_vulnerable.py" &
done
```

## Troubleshooting

### Common Issues

1. **Services not starting**
   ```bash
   # Check logs
   docker-compose logs -f backend
   docker-compose logs -f celery-worker
   ```

2. **Database connection errors**
   - Verify Supabase credentials in .env
   - Check if tables are created

3. **Scanning tools not found**
   ```bash
   # Rebuild backend image
   docker-compose build backend
   ```

4. **WebSocket connection failed**
   - Check if Redis is running
   - Verify CORS settings

### Debug Mode
```bash
# Run backend in debug mode
docker-compose run --rm backend python -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

## Sample Vulnerable Code Files

### Python (test_vulnerable.py)
```python
# Multiple vulnerabilities for testing
import pickle
import subprocess

# Insecure deserialization
def load_data(data):
    return pickle.loads(data)  # CWE-502

# Command injection
def ping(host):
    subprocess.call(f"ping -c 1 {host}", shell=True)  # CWE-78

# Hardcoded API key
API_KEY = "sk-1234567890abcdef"  # CWE-798
```

### JavaScript (test_vulnerable.js)
```javascript
// XSS vulnerability
function displayUser(name) {
    document.getElementById('user').innerHTML = name; // XSS
}

// SQL Injection
function getUser(id) {
    const query = `SELECT * FROM users WHERE id = ${id}`; // SQL Injection
    return db.query(query);
}
```

## API Endpoints Reference

- `POST /api/auth/login` - User login
- `POST /api/auth/register` - User registration
- `POST /api/auth/demo-token` - Get demo token
- `GET /api/projects` - List projects
- `POST /api/projects` - Create project
- `POST /api/scans` - Create scan
- `GET /api/scans/{id}/results` - Get scan results
- `GET /api/scans/{id}/progress` - Get scan progress
- `POST /api/ai/analyze-vulnerability` - Analyze with AI
- `GET /api/export/scan/{id}` - Export scan report
- `WS /ws/scan/{id}` - WebSocket for scan progress

## Next Steps

After testing, you can:
1. Deploy to production using the Docker setup
2. Configure monitoring with Prometheus/Grafana
3. Set up CI/CD pipeline
4. Add custom security rules
5. Integrate with your development workflow