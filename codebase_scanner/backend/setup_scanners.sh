#!/bin/bash

# Setup script for security scanning tools
# Run this script to install all required security scanning tools

set -e

echo "🔧 Installing Security Scanning Tools..."

# Install Python packages
echo "📦 Installing Python security tools..."
pip install semgrep bandit safety

# Install gitleaks (binary)
echo "🔍 Installing gitleaks..."

# Detect OS and architecture
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

# Map architecture names
case $ARCH in
    x86_64) ARCH="x86_64" ;;
    aarch64|arm64) ARCH="arm64" ;;
    *) echo "Unsupported architecture: $ARCH"; exit 1 ;;
esac

# Download and install gitleaks
GITLEAKS_VERSION="8.18.0"
GITLEAKS_URL="https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_${OS}_${ARCH}.tar.gz"

echo "Downloading gitleaks from: $GITLEAKS_URL"

# Create temp directory
TEMP_DIR=$(mktemp -d)
cd "$TEMP_DIR"

# Download and extract
curl -L "$GITLEAKS_URL" -o gitleaks.tar.gz
tar -xzf gitleaks.tar.gz

# Install to /usr/local/bin (requires sudo) or current directory
if [ -w "/usr/local/bin" ]; then
    echo "Installing gitleaks to /usr/local/bin..."
    mv gitleaks /usr/local/bin/
elif command -v sudo >/dev/null 2>&1; then
    echo "Installing gitleaks to /usr/local/bin (requires sudo)..."
    sudo mv gitleaks /usr/local/bin/
else
    echo "Installing gitleaks to current directory..."
    mv gitleaks "$OLDPWD/"
    echo "⚠️  Note: gitleaks installed to current directory. Add to PATH if needed."
fi

# Cleanup
cd "$OLDPWD"
rm -rf "$TEMP_DIR"

echo "✅ Verifying installations..."

# Test installations
echo "Testing semgrep..."
semgrep --version

echo "Testing bandit..."
bandit --version

echo "Testing safety..."
safety --version

echo "Testing gitleaks..."
gitleaks version

echo ""
echo "🎉 All security scanning tools installed successfully!"
echo ""
echo "Available tools:"
echo "  • Semgrep    - Multi-language SAST (Static Application Security Testing)"
echo "  • Bandit     - Python security linter"
echo "  • Safety     - Python dependency vulnerability scanner"
echo "  • Gitleaks   - Git secrets scanner"
echo ""
echo "You can now run real security scans using the web application!"