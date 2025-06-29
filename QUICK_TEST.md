# Quick Testing Guide

## 1. Start the Application

```bash
cd /Users/jimmylam/Documents/security
docker-compose up -d
```

Wait 30 seconds for all services to start.

## 2. Check Services Are Running

```bash
# Check all containers are up
docker-compose ps

# Test backend is responding
curl http://localhost:8000/health

# Open frontend in browser
open http://localhost:5173
```

## 3. Manual Testing Steps

### Step 1: Register a User
1. Go to http://localhost:5173
2. Click "create a new account"
3. Fill in:
   - Email: test@example.com
   - Username: testuser
   - Password: test123
   - Full Name: Test User
4. Click Register

### Step 2: Login
1. Use the credentials you just created
2. You should see the Dashboard

### Step 3: Create a Project
1. Click "Projects" in the navigation
2. Click "Create Project" button
3. Enter:
   - Name: "Test Project"
   - Description: "My first security scan"
   - GitHub URL: https://github.com/OWASP/NodeGoat
4. Click "Create"

### Step 4: Run a Scan
1. Click on your project name
2. Click "Start Scan"
3. Select "Security" scan type
4. Click "Start"
5. Wait for scan to complete (1-2 minutes)

### Step 5: View Results
1. Once scan is complete, click "View Results"
2. You should see security vulnerabilities found
3. Check different severity levels

### Step 6: Generate Report
1. Click "Generate Report"
2. Select "Security Report"
3. View the report summary
4. Check the security score

## 4. Automated Testing

Run the automated test script:

```bash
cd /Users/jimmylam/Documents/security
./test_app.sh
```

This will automatically:
- Register a test user
- Create a project
- Upload vulnerable code
- Run a security scan
- Check results
- Generate a report

## 5. Test with Real Vulnerable Apps

Test with these known vulnerable applications:

1. **OWASP NodeGoat** (JavaScript)
   - URL: https://github.com/OWASP/NodeGoat
   - Expected: XSS, SQL Injection, etc.

2. **OWASP Juice Shop** (JavaScript/TypeScript)
   - URL: https://github.com/juice-shop/juice-shop
   - Expected: Multiple vulnerabilities

3. **Damn Vulnerable Python Web App**
   - URL: https://github.com/anxolerd/dvpwa
   - Expected: Python vulnerabilities

## 6. Check Logs for Errors

```bash
# Check backend logs
docker-compose logs backend

# Check worker logs
docker-compose logs celery_worker

# Follow all logs
docker-compose logs -f
```

## 7. Common Issues & Solutions

### Frontend not loading
```bash
docker-compose restart frontend
```

### Backend API errors
```bash
docker-compose restart backend
```

### Database connection issues
```bash
docker-compose restart postgres
docker-compose restart backend
```

### Scans not starting
```bash
# Check if worker is running
docker-compose logs celery_worker
docker-compose restart celery_worker
```

## 8. Stop Everything

```bash
docker-compose down
```

To completely reset (including database):
```bash
docker-compose down -v
```