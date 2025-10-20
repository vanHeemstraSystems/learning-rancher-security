# Dockerfile for Rancher Security Audit Tool

FROM python:3.11-slim

LABEL maintainer=“security@example.com”
LABEL description=“Rancher Security Audit Tool - Automated security scanning for Rancher deployments”
LABEL version=“1.0”

# Set working directory

WORKDIR /app

# Install system dependencies

RUN apt-get update && apt-get install -y –no-install-recommends   
curl   
ca-certificates   
cron   
&& rm -rf /var/lib/apt/lists/*

# Copy requirements first for better layer caching

COPY requirements.txt .

# Install Python dependencies

RUN pip install –no-cache-dir –upgrade pip &&   
pip install –no-cache-dir -r requirements.txt

# Copy application files

COPY rancher_security_audit.py .
COPY run-audit.sh .
COPY docker-entrypoint.sh .

# Make scripts executable

RUN chmod +x run-audit.sh docker-entrypoint.sh

# Create necessary directories

RUN mkdir -p /reports /app/logs

# Create config directory

RUN mkdir -p /app/config

# Create a non-root user for security

RUN useradd -m -u 1000 -s /bin/bash auditor &&   
chown -R auditor:auditor /app /reports

# Set up cron job for scheduled scans

# Default: Run at 2 AM daily (can be overridden via environment variable)

RUN echo “0 2 * * * auditor /app/run-audit.sh >> /app/logs/cron.log 2>&1” > /etc/cron.d/audit-cron &&   
chmod 0644 /etc/cron.d/audit-cron &&   
crontab -u auditor /etc/cron.d/audit-cron

# Health check

HEALTHCHECK –interval=30s –timeout=10s –start-period=5s –retries=3   
CMD python -c “import sys; sys.exit(0)” || exit 1

# Switch to non-root user

USER auditor

# Set environment variables

ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# Expose no ports (this is a client application)

# Entry point

ENTRYPOINT [”/app/docker-entrypoint.sh”]

# Default command - keep container running for scheduled scans

CMD [“tail”, “-f”, “/dev/null”]
