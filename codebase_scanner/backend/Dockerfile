# Production Dockerfile for Codebase Scanner Backend
FROM python:3.11-slim AS base

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    LOG_DIR=/app/logs \
    TEMP_DIR=/app/temp

# Install system dependencies and additional tools
RUN apt-get update && apt-get install -y \
    git \
    curl \
    wget \
    build-essential \
    libmagic1 \
    nodejs \
    npm \
    golang-go \
    ruby-full \
    php-cli \
    default-jdk \
    python3-dev \
    libssl-dev \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Python security scanning tools
RUN pip install --no-cache-dir \
    semgrep==1.45.0 \
    bandit==1.7.5 \
    safety==3.0.0 \
    detect-secrets==1.4.0 \
    pylint \
    flake8 \
    mypy \
    checkov \
    njsscan \
    pysast

# Install Node.js security tools
RUN npm install -g \
    eslint \
    eslint-plugin-security \
    retire \
    @bearer/cli \
    nodejsscan

# Install Ruby security tools (if Ruby projects detected)
RUN gem install brakeman bundler-audit

# Install GitLeaks for secret scanning
RUN curl -sSfL https://github.com/gitleaks/gitleaks/releases/download/v8.18.0/gitleaks_8.18.0_linux_x64.tar.gz | tar -xz -C /usr/local/bin && \
    chmod +x /usr/local/bin/gitleaks

# Install TruffleHog v3
RUN curl -sSfL https://github.com/trufflesecurity/trufflehog/releases/download/v3.63.0/trufflehog_3.63.0_linux_amd64.tar.gz | tar -xz -C /usr/local/bin && \
    chmod +x /usr/local/bin/trufflehog

# Install Grype for vulnerability scanning
RUN curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin

# Install Trivy for container/IaC scanning
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

# Install gosec for Go security
RUN go install github.com/securego/gosec/v2/cmd/gosec@latest && \
    cp /root/go/bin/gosec /usr/local/bin/

# Install mobsfscan for mobile app scanning
RUN pip install mobsfscan

# Create app user
RUN groupadd -r appuser && useradd -r -g appuser appuser

# Set work directory
WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create necessary directories
RUN mkdir -p /app/logs /app/temp /app/uploads && \
    chown -R appuser:appuser /app

# Copy and set permissions for scripts
COPY --chmod=755 scripts/start.sh /app/scripts/

# Switch to non-root user
USER appuser

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Start command with production settings
CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers ${WORKERS:-4} --log-level ${LOG_LEVEL:-info}"]