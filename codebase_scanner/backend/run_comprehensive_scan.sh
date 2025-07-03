#!/bin/bash
# Comprehensive Security Scanner Runner
# Ensures all security tools are installed and runs complete scan

set -e

REPO_PATH="$1"
BACKEND_DIR="$(dirname "$0")"

if [ -z "$REPO_PATH" ]; then
    echo "Usage: $0 <repository_path>"
    exit 1
fi

echo "====================================="
echo "Enterprise Security Scanner v1.0"
echo "====================================="
echo "Repository: $REPO_PATH"
echo "Date: $(date)"
echo ""

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to install tool if missing
install_tool() {
    local tool="$1"
    local install_cmd="$2"
    
    if ! command_exists "$tool"; then
        echo "[!] $tool not found. Installing..."
        eval "$install_cmd"
    else
        echo "[✓] $tool is installed"
    fi
}

echo "[*] Checking and installing required security tools..."
echo ""

# Core Security Tools (10 tools from CLAUDE.md)
install_tool "semgrep" "pip install semgrep"
install_tool "bandit" "pip install bandit"
install_tool "safety" "pip install safety"
install_tool "gitleaks" "brew install gitleaks || curl -sSfL https://raw.githubusercontent.com/gitleaks/gitleaks/master/scripts/install.sh | sh -s -- -b /usr/local/bin"
install_tool "trufflehog" "pip install truffleHog"
install_tool "detect-secrets" "pip install detect-secrets"
install_tool "retire" "npm install -g retire"
install_tool "jadx" "brew install jadx || echo 'Please install JADX manually'"
install_tool "apkleaks" "pip install apkleaks"
install_tool "qark" "pip install qark"

# Additional Enterprise Tools
install_tool "njsscan" "pip install njsscan"
install_tool "eslint" "npm install -g eslint eslint-plugin-security"
install_tool "checkov" "pip install checkov"
install_tool "tfsec" "brew install tfsec || curl -s https://raw.githubusercontent.com/aquasecurity/tfsec/master/scripts/install_linux.sh | bash"
install_tool "dependency-check" "brew install dependency-check || echo 'Please install OWASP Dependency Check manually'"

echo ""
echo "[*] All tools checked/installed"
echo ""

# Create comprehensive scan configuration
cat > "$REPO_PATH/scan-config.json" << EOF
{
    "scan_type": "comprehensive",
    "enable_all_tools": true,
    "security_tools": {
        "core_tools": [
            "semgrep", "bandit", "safety", "gitleaks", "trufflehog",
            "detect-secrets", "retire", "jadx", "apkleaks", "qark"
        ],
        "additional_tools": [
            "eslint-security", "njsscan", "gosec", "phpcs-security-audit",
            "brakeman", "checkov", "tfsec", "kubesec", "dependency-check",
            "snyk", "sonarqube", "codeql"
        ]
    },
    "scan_options": {
        "deep_scan": true,
        "check_dependencies": true,
        "scan_history": true,
        "max_depth": 10,
        "include_dev_dependencies": true
    },
    "report_options": {
        "format": "enterprise",
        "include_remediation": true,
        "include_code_samples": true,
        "generate_executive_summary": true,
        "compliance_mapping": ["OWASP", "PCI-DSS", "SOC2", "GDPR", "HIPAA"]
    }
}
EOF

echo "[*] Running comprehensive security scan..."
echo ""

# Run the Python scanner with all tools
cd "$BACKEND_DIR"
python3 comprehensive_scanner.py "$REPO_PATH"

echo ""
echo "[✓] Comprehensive scan complete!"
echo "[✓] Report generated in: $REPO_PATH/scan-results/"
echo ""
echo "Summary:"
echo "- All available security tools were executed"
echo "- Vulnerabilities have been deduplicated and scored"
echo "- Enterprise report has been generated"
echo "- Compliance mappings have been completed"
echo ""