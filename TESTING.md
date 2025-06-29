# Testing Guide for Codebase Scanner

## Quick Start Testing

### 1. Start the Application

```bash
cd /Users/jimmylam/Documents/security

# Start all services
docker-compose up -d

# Check if services are running
docker-compose ps

# View logs
docker-compose logs -f
```

### 2. Create Test User

Open your browser and go to http://localhost:5173

1. Click "create a new account"
2. Register with:
   - Email: test@example.com
   - Username: testuser
   - Password: testpass123
   - Full Name: Test User

### 3. Test Basic Functionality

#### A. Create a Test Project

1. Login with your credentials
2. Navigate to "Projects" from the menu
3. Click "Create Project"
4. Fill in:
   - Name: "Test Security Project"
   - Description: "Testing security scanning"
   - GitHub URL: https://github.com/juice-shop/juice-shop (vulnerable app for testing)

#### B. Upload Test Code

If you want to test with a local file:

1. Create a vulnerable Python file for testing
2. Zip it and upload through the project interface

#### C. Run a Security Scan

1. Go to your project details
2. Click "Start Scan"
3. Select scan type: "Full"
4. Watch the scan progress

### 4. API Testing

Test the API directly using curl or Postman:

```bash
# Get access token
curl -X POST "http://localhost:8000/api/auth/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=testuser&password=testpass123"

# Save the token
export TOKEN="your_access_token_here"

# List projects
curl -X GET "http://localhost:8000/api/projects" \
  -H "Authorization: Bearer $TOKEN"

# Create a project
curl -X POST "http://localhost:8000/api/projects" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "API Test Project",
    "description": "Created via API",
    "github_repo_url": "https://github.com/OWASP/NodeGoat"
  }'

# Start a scan
curl -X POST "http://localhost:8000/api/scans" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "project_id": 1,
    "scan_type": "security"
  }'
```

## Detailed Testing Scenarios

### Test Case 1: User Registration and Authentication

1. **Register New User**
   - Navigate to http://localhost:5173/login
   - Click "create a new account"
   - Fill all fields
   - Verify registration success

2. **Login**
   - Use registered credentials
   - Verify redirect to dashboard
   - Check user info in top-right menu

3. **Logout**
   - Click user menu → Sign out
   - Verify redirect to login page

### Test Case 2: Project Management

1. **Create Project with GitHub URL**
   ```json
   {
     "name": "OWASP WebGoat",
     "github_repo_url": "https://github.com/WebGoat/WebGoat"
   }
   ```

2. **Upload Code ZIP**
   - Create test files with vulnerabilities
   - ZIP and upload through UI
   - Verify upload success

3. **Update Project Settings**
   - Change scan configuration
   - Add excluded paths
   - Update project name

### Test Case 3: Security Scanning

1. **Run Different Scan Types**
   - Security scan
   - Quality scan
   - Performance scan
   - Full scan

2. **Monitor Scan Progress**
   - Check scan status updates
   - View real-time results
   - Cancel running scan

### Test Case 4: View Results and Reports

1. **View Scan Results**
   - Check vulnerability details
   - Filter by severity
   - Mark false positives

2. **Generate Reports**
   - Security report
   - Compliance report
   - Executive summary

3. **Download Reports**
   - JSON format
   - SARIF format (for GitHub)

## Test Data

### Vulnerable Code Samples

Create these files to test vulnerability detection:

**vulnerable_python.py**
```python
import os
import sqlite3
from flask import Flask, request

app = Flask(__name__)

# SQL Injection vulnerability
@app.route('/user')
def get_user():
    user_id = request.args.get('id')
    conn = sqlite3.connect('users.db')
    # VULNERABLE: Direct string concatenation
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor = conn.execute(query)
    return str(cursor.fetchall())

# Command Injection vulnerability
@app.route('/ping')
def ping():
    host = request.args.get('host')
    # VULNERABLE: Direct command execution
    response = os.system(f"ping -c 1 {host}")
    return str(response)

# Hardcoded credentials
API_KEY = "sk-1234567890abcdef"
DATABASE_PASSWORD = "admin123"

# Weak cryptography
import md5  # Deprecated and insecure
def hash_password(password):
    return md5.new(password).hexdigest()
```

**vulnerable_javascript.js**
```javascript
const express = require('express');
const app = express();

// XSS vulnerability
app.get('/search', (req, res) => {
    const query = req.query.q;
    // VULNERABLE: Direct HTML injection
    res.send(`<h1>Search results for: ${query}</h1>`);
});

// SQL Injection
app.get('/user/:id', (req, res) => {
    const userId = req.params.id;
    // VULNERABLE: String concatenation in SQL
    const query = `SELECT * FROM users WHERE id = ${userId}`;
    db.query(query, (err, results) => {
        res.json(results);
    });
});

// Insecure Random
function generateToken() {
    // VULNERABLE: Math.random() is not cryptographically secure
    return Math.random().toString(36).substr(2);
}

// Hardcoded secrets
const JWT_SECRET = 'my-secret-key';
const API_KEY = 'sk_test_1234567890';
```

## Troubleshooting

### Common Issues

1. **Services not starting**
   ```bash
   # Check logs
   docker-compose logs postgres
   docker-compose logs backend
   docker-compose logs frontend
   
   # Restart services
   docker-compose restart
   ```

2. **Database connection errors**
   ```bash
   # Check database is running
   docker-compose exec postgres pg_isready -U scanner_user
   
   # Reset database
   docker-compose down -v
   docker-compose up -d
   ```

3. **Frontend not loading**
   ```bash
   # Check frontend logs
   docker-compose logs frontend
   
   # Rebuild frontend
   docker-compose build frontend
   docker-compose up -d frontend
   ```

4. **Scan not starting**
   ```bash
   # Check celery worker
   docker-compose logs celery_worker
   
   # Check Redis connection
   docker-compose exec redis redis-cli ping
   ```

## Performance Testing

### Load Testing with Apache Bench

```bash
# Install Apache Bench
apt-get install apache2-utils  # Ubuntu/Debian
brew install apache-bench      # macOS

# Test API endpoints
ab -n 100 -c 10 -H "Authorization: Bearer $TOKEN" http://localhost:8000/api/projects/
```

### Monitor Resource Usage

```bash
# Monitor Docker containers
docker stats

# Check specific service
docker-compose logs -f backend | grep -i error
```

## Security Testing

### Test Authentication

1. Try accessing protected endpoints without token
2. Test with expired token
3. Test with invalid token

### Test Input Validation

1. Try SQL injection in search fields
2. Test XSS in project names
3. Upload oversized files
4. Upload non-zip files

### Test Rate Limiting

Make multiple rapid requests to check rate limiting:

```bash
for i in {1..50}; do
  curl -X GET "http://localhost:8000/api/projects" \
    -H "Authorization: Bearer $TOKEN"
done
```

## Automated Testing

### Run Backend Tests

```bash
docker-compose exec backend pytest
```

### Run Frontend Tests

```bash
docker-compose exec frontend npm test
```

## Expected Results

### Successful Scan Output

When scanning the vulnerable code above, you should see:

1. **Python Issues:**
   - SQL Injection in `get_user()`
   - Command Injection in `ping()`
   - Hardcoded credentials (API_KEY, DATABASE_PASSWORD)
   - Use of deprecated MD5 hashing

2. **JavaScript Issues:**
   - XSS vulnerability in search endpoint
   - SQL Injection in user endpoint
   - Insecure random number generation
   - Hardcoded secrets

3. **Severity Distribution:**
   - Critical: 2-3 issues
   - High: 3-4 issues
   - Medium: 2-3 issues
   - Low: Various info-level issues

## Next Steps

After basic testing:

1. Test GitHub OAuth integration
2. Test webhook integration
3. Test report generation and download
4. Test false positive marking
5. Test concurrent scans
6. Test with large codebases