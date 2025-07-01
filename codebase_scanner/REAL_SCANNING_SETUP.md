# Real Security Scanning Setup

This document explains how to activate the real security scanning capabilities of the Codebase Scanner application.

## 🎯 Overview

The application includes a complete real scanning system using industry-standard security tools:

- **Semgrep** - Multi-language SAST (Static Application Security Testing)
- **Bandit** - Python security linter for identifying common security issues
- **Safety** - Python dependency vulnerability scanner using CVE database
- **Gitleaks** - Git secrets scanner for detecting API keys, passwords, etc.

## 🚀 Quick Setup

### 1. Install Scanning Tools

Run the setup script to install all required tools:

```bash
cd backend
./setup_scanners.sh
```

### 2. Verify Installation

Test that all tools are working by visiting the scanner tools endpoint:

```bash
curl http://localhost:8000/api/test/scanner-tools
```

Or use the "🔧 Scanner Tools" button in the frontend UI.

### 3. Start Real Scanning

The frontend has been updated to use real scanning instead of simulation. When you click "Scan Now" on any project, it will:

1. **Repository Scanning**: If the project has a GitHub URL, it clones and scans the actual repository
2. **Demo Scanning**: If no repository URL, it scans the OWASP NodeGoat project for demonstration

## 🔧 Manual Installation

If the setup script doesn't work for your environment:

### Python Tools
```bash
pip install semgrep bandit safety
```

### Gitleaks (Binary)
```bash
# macOS with Homebrew
brew install gitleaks

# Linux/macOS manual installation
GITLEAKS_VERSION="8.18.0"
curl -L "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" -o gitleaks.tar.gz
tar -xzf gitleaks.tar.gz
sudo mv gitleaks /usr/local/bin/
```

## 🧠 AI-Powered Analysis

The real scanning system integrates with Claude AI for:

- **Vulnerability Analysis**: Deep security analysis of each finding
- **Fix Suggestions**: Code-level remediation recommendations  
- **Compliance Mapping**: Mapping to OWASP, SANS, ISO 27001, SOC 2, GDPR
- **Plain English Explanations**: Developer-friendly explanations

Click "Analyze with Claude" on any vulnerability to get AI-powered insights.

## 🏗️ Architecture

```
Frontend (React) → FastAPI Backend → Scanner Service → Security Tools
                                 ↓
                            Claude AI Analysis ← Real Vulnerabilities
                                 ↓
                            PostgreSQL Database
```

## 🔍 What Gets Scanned

### Semgrep Detects:
- SQL injection vulnerabilities
- Cross-site scripting (XSS)
- Path traversal attacks
- Insecure cryptographic practices
- Authentication bypass issues

### Bandit Finds:
- Hardcoded passwords and secrets
- Unsafe use of eval() and exec()
- SQL injection in Python code
- Insecure random number generation
- Shell injection vulnerabilities

### Safety Identifies:
- Known vulnerabilities in Python packages
- Outdated dependencies with security fixes
- CVE-rated security issues
- License compliance issues

### Gitleaks Discovers:
- API keys and access tokens
- Database connection strings
- AWS credentials and secrets
- Private keys and certificates
- Custom secret patterns

## 📊 Real Results vs Simulation

**Simulation (Old)**:
- ❌ Generated 3 fake vulnerabilities
- ❌ Static mock data
- ❌ No real code analysis

**Real Scanning (New)**:
- ✅ Analyzes actual code files
- ✅ Detects real security issues
- ✅ Provides actionable fix guidance
- ✅ Maps to compliance frameworks
- ✅ Integrates with CI/CD pipelines

## 🛠️ Troubleshooting

### Tools Not Found
1. Check if tools are in PATH: `which semgrep bandit safety gitleaks`
2. Re-run setup script: `./setup_scanners.sh`
3. Install manually using package managers

### Scanning Fails
1. Check scanner tools status: Visit `/api/test/scanner-tools`
2. Verify repository access: Ensure GitHub repos are public or credentials provided
3. Check logs: Monitor backend logs for detailed error messages

### AI Analysis Issues
1. Verify Anthropic API key: Set `ANTHROPIC_API_KEY` environment variable
2. Check rate limits: Monitor API usage and limits
3. Test endpoint: Use "Analyze with Claude" on individual vulnerabilities

## 🔐 Production Deployment

For production environments:

1. **Install tools in Docker container**:
```dockerfile
RUN pip install semgrep bandit safety && \
    curl -L "https://github.com/gitleaks/gitleaks/releases/download/v8.18.0/gitleaks_8.18.0_linux_x64.tar.gz" | \
    tar -xz -C /usr/local/bin/
```

2. **Configure environment variables**:
```bash
ANTHROPIC_API_KEY=your_claude_api_key
TEMP_DIR=/tmp/scans
```

3. **Set up persistent storage** for scan results and temporary files

## 📈 Performance

Real scanning performance depends on:
- **Repository size**: Larger repos take longer to clone and scan
- **File count**: More files = longer scan time
- **Scanner configuration**: Comprehensive scans are more thorough but slower
- **Network speed**: Repository cloning speed

Typical scan times:
- Small repo (< 100 files): 30-60 seconds
- Medium repo (100-1000 files): 2-5 minutes  
- Large repo (1000+ files): 5-15 minutes

## 🎉 Next Steps

1. Click "🔧 Scanner Tools" to verify your setup
2. Create a project with a GitHub repository URL
3. Click "Scan Now" to start real scanning
4. View real vulnerabilities in the results page
5. Use "Analyze with Claude" for AI-powered insights

The application is now using real security scanning instead of simulation!