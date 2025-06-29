FROM ubuntu:22.04

# Install base tools
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    nodejs \
    npm \
    git \
    curl \
    wget \
    default-jre \
    golang-go \
    ruby \
    php \
    && rm -rf /var/lib/apt/lists/*

# Install language-specific security tools
# Python
RUN pip3 install bandit safety pylint

# JavaScript/TypeScript  
RUN npm install -g eslint eslint-plugin-security retire @microsoft/eslint-formatter-sarif

# Java
RUN wget https://github.com/spotbugs/spotbugs/releases/download/4.7.3/spotbugs-4.7.3.tgz \
    && tar -xzf spotbugs-4.7.3.tgz -C /opt \
    && rm spotbugs-4.7.3.tgz

# Go
RUN go install github.com/securego/gosec/v2/cmd/gosec@latest

# Ruby
RUN gem install brakeman

# PHP
RUN wget https://github.com/squizlabs/PHP_CodeSniffer/releases/download/3.7.2/phpcs.phar \
    && chmod +x phpcs.phar \
    && mv phpcs.phar /usr/local/bin/phpcs

# Install Semgrep
RUN pip3 install semgrep

# Install OWASP Dependency Check
RUN wget https://github.com/jeremylong/DependencyCheck/releases/download/v8.4.3/dependency-check-8.4.3-release.zip \
    && unzip dependency-check-8.4.3-release.zip -d /opt \
    && rm dependency-check-8.4.3-release.zip

# Install Trivy for container scanning
RUN wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | apt-key add - \
    && echo "deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" | tee -a /etc/apt/sources.list.d/trivy.list \
    && apt-get update \
    && apt-get install -y trivy

# Create working directory
WORKDIR /scans

# Set PATH
ENV PATH="/opt/spotbugs-4.7.3/bin:/opt/dependency-check/bin:${PATH}:/root/go/bin"

CMD ["/bin/bash"]