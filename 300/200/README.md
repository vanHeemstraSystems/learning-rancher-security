# Rancher Security Audit Tool - Docker Setup Guide

Complete guide for running the Rancher Security Audit Tool against a Dockerized Rancher deployment.

## 📋 Table of Contents

- [Overview](#overview)
- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
- [Architecture](#architecture)
- [Detailed Setup](#detailed-setup)
- [Running Security Audits](#running-security-audits)
- [Troubleshooting](#troubleshooting)
- [Advanced Configurations](#advanced-configurations)

## 🎯 Overview

This setup provides a complete containerized environment for:

- Running Rancher in Docker for testing/learning
- Deploying the Security Audit Tool as a container
- Automated security scanning on a schedule
- Generating and accessing audit reports

**⚠️ Important**: This Docker setup is designed for testing and learning. For production Rancher deployments, use Kubernetes-based installations.

## 📦 Prerequisites

- Docker Engine 20.10 or later
- Docker Compose V2 or later
- At least 4GB of free RAM
- At least 10GB of free disk space
- Basic understanding of Docker and Rancher

### Check Your Setup

```bash
# Verify Docker installation
docker --version
# Should output: Docker version 20.10.x or later

# Verify Docker Compose
docker compose version
# Should output: Docker Compose version v2.x.x or later

# Check available resources
docker system df
```

## 🚀 Quick Start

Get up and running in 5 minutes:

```bash
# 1. Clone the repository
git clone https://github.com/yourusername/Learning-Rancher-Security.git
cd Learning-Rancher-Security

# 2. Create environment configuration
cp .env.example .env
# Edit .env with your preferences (optional for testing)

# 3. Start Rancher and audit tool
docker compose up -d

# 4. Wait for Rancher to initialize (2-3 minutes)
docker compose logs -f rancher

# 5. Access Rancher UI
# Open browser to: https://localhost:8443
# Note: Accept the self-signed certificate warning

# 6. Get initial admin password
docker compose exec rancher cat /var/lib/rancher/server/bootstrap-secret

# 7. Complete Rancher setup in the UI
# - Set new admin password
# - Create API key: User menu → API & Keys → Add Key
# - Save the access key and secret key

# 8. Configure the audit tool
nano .env
# Add your API credentials:
# RANCHER_ACCESS_KEY=token-xxxxx
# RANCHER_SECRET_KEY=your-secret-key

# 9. Run your first audit
docker compose exec audit-tool python rancher_security_audit.py \
  --config /app/config.yaml \
  --full-scan

# 10. View the report
# Reports are saved to ./reports/ directory
open reports/latest-audit.html
```

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Docker Compose Stack                     │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  ┌─────────────────────┐      ┌──────────────────────┐     │
│  │   Rancher Server    │      │   Audit Tool         │     │
│  │   (rancher/rancher) │◄─────┤   (Python App)       │     │
│  │                     │ API  │                      │     │
│  │   Ports: 8080/8443  │      │   Scheduled Scans    │     │
│  │                     │      │                      │     │
│  └─────────────────────┘      └──────────────────────┘     │
│           │                             │                    │
│           │                             │                    │
│           ▼                             ▼                    │
│  ┌─────────────────┐          ┌──────────────────┐         │
│  │  rancher-data   │          │     reports/     │         │
│  │  (Docker Volume)│          │  (Bind Mount)    │         │
│  └─────────────────┘          └──────────────────┘         │
│                                                               │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
                  ┌──────────────────┐
                  │   Host Machine   │
                  │   Browser Access │
                  └──────────────────┘
```

## 📝 Detailed Setup

### Step 1: Prepare the Environment

```bash
# Create necessary directories
mkdir -p reports logs

# Set proper permissions
chmod 755 reports logs

# Copy environment template
cp .env.example .env
```

### Step 2: Configure Environment Variables

Edit `.env` file:

```bash
# Rancher Configuration
RANCHER_VERSION=v2.8.0
RANCHER_HTTP_PORT=8080
RANCHER_HTTPS_PORT=8443
RANCHER_HOSTNAME=localhost

# Audit Tool Configuration
RANCHER_URL=https://rancher:443
RANCHER_ACCESS_KEY=
RANCHER_SECRET_KEY=
VERIFY_SSL=false

# Scan Schedule (cron format)
AUDIT_SCHEDULE=0 2 * * *

# Report Settings
REPORT_FORMAT=html
REPORT_RETENTION_DAYS=30
```

### Step 3: Launch the Stack

```bash
# Start all services
docker compose up -d

# Verify services are running
docker compose ps

# Expected output:
# NAME                    STATUS              PORTS
# rancher                 Up (healthy)        0.0.0.0:8080->80/tcp, 0.0.0.0:8443->443/tcp
# audit-tool              Up                  
```

### Step 4: Initialize Rancher

```bash
# Monitor Rancher startup logs
docker compose logs -f rancher

# Wait for message: "Bootstrap password: xxxxx"
# Or retrieve it manually:
docker compose exec rancher cat /var/lib/rancher/server/bootstrap-secret
```

**Initial Setup in Rancher UI:**

1. Navigate to `https://localhost:8443`
1. Accept self-signed certificate warning
1. Enter bootstrap password
1. Set new admin password
1. Accept terms and conditions
1. Configure server URL (use default for testing)

### Step 5: Generate API Credentials

**In Rancher UI:**

1. Click on user avatar (top-right)
1. Select **API & Keys**
1. Click **Add Key**
1. Fill in details:
- **Description**: Security Audit Tool
- **Expiration**: 90 days
- **Scope**: No scope (full access for testing)
1. Click **Create**
1. **Copy both keys immediately** - they won’t be shown again!

**Update .env file:**

```bash
# Edit .env and add your credentials
RANCHER_ACCESS_KEY=token-abc123
RANCHER_SECRET_KEY=secret-xyz789

# Reload audit tool configuration
docker compose restart audit-tool
```

### Step 6: Verify Connectivity

```bash
# Test API connection from audit tool
docker compose exec audit-tool python -c "
import requests
import os
url = os.getenv('RANCHER_URL')
auth = (os.getenv('RANCHER_ACCESS_KEY'), os.getenv('RANCHER_SECRET_KEY'))
response = requests.get(f'{url}/v3', auth=auth, verify=False)
print(f'Connection status: {response.status_code}')
print(f'Rancher version: {response.json().get(\"version\")}')
"
```

Expected output:

```
Connection status: 200
Rancher version: v2.8.0
```

## 🔍 Running Security Audits

### Manual Audit

```bash
# Run full security audit
docker compose exec audit-tool python rancher_security_audit.py \
  --config /app/config.yaml \
  --full-scan \
  --format html \
  --output /reports/manual-audit-$(date +%Y%m%d-%H%M%S).html

# View the report
ls -lh reports/
```

### Run Specific Checks

```bash
# Check only authentication
docker compose exec audit-tool python rancher_security_audit.py \
  --config /app/config.yaml \
  --check authentication_config

# Check API tokens
docker compose exec audit-tool python rancher_security_audit.py \
  --config /app/config.yaml \
  --check api_tokens

# Check RBAC configuration
docker compose exec audit-tool python rancher_security_audit.py \
  --config /app/config.yaml \
  --check rbac_configuration
```

### Generate Different Report Formats

```bash
# HTML Report (default)
docker compose exec audit-tool python rancher_security_audit.py \
  --config /app/config.yaml \
  --full-scan \
  --format html \
  --output /reports/audit.html

# JSON Report (for automation)
docker compose exec audit-tool python rancher_security_audit.py \
  --config /app/config.yaml \
  --full-scan \
  --format json \
  --output /reports/audit.json

# Text Report (for terminals)
docker compose exec audit-tool python rancher_security_audit.py \
  --config /app/config.yaml \
  --full-scan \
  --format text
```

### Automated Scheduled Scans

The audit tool runs automatically based on `AUDIT_SCHEDULE` in `.env`:

```bash
# View scheduled scan logs
docker compose logs -f audit-tool

# Force a scheduled scan now
docker compose exec audit-tool sh -c "/app/run-audit.sh"

# Check cron status
docker compose exec audit-tool crontab -l
```

### Accessing Reports

Reports are saved to the `./reports/` directory on your host:

```bash
# List all reports
ls -lh reports/

# View latest report (macOS)
open reports/latest-audit.html

# View latest report (Linux)
xdg-open reports/latest-audit.html

# View latest report (Windows)
start reports/latest-audit.html

# Serve reports via HTTP for remote access
cd reports && python3 -m http.server 8888
# Access via: http://localhost:8888
```

## 🔧 Troubleshooting

### Rancher Won’t Start

```bash
# Check Rancher logs
docker compose logs rancher

# Common issues:
# 1. Port already in use
sudo lsof -i :8443
# Kill the process or change RANCHER_HTTPS_PORT in .env

# 2. Insufficient memory
docker stats rancher
# Increase Docker memory limit

# 3. Volume permission issues
docker compose down -v
docker volume prune
docker compose up -d
```

### Audit Tool Can’t Connect

```bash
# Verify network connectivity
docker compose exec audit-tool ping -c 3 rancher

# Check if Rancher is ready
docker compose exec audit-tool curl -k https://rancher/v3

# Verify credentials
docker compose exec audit-tool env | grep RANCHER

# Test authentication
docker compose exec audit-tool python -c "
import requests, os
auth = (os.getenv('RANCHER_ACCESS_KEY'), os.getenv('RANCHER_SECRET_KEY'))
resp = requests.get('https://rancher/v3', auth=auth, verify=False)
print(resp.status_code)
"
```

### SSL Certificate Issues

```bash
# For development, disable SSL verification
# In .env:
VERIFY_SSL=false

# For production, add proper certificates
# See "Adding Custom Certificates" section below
```

### Reports Not Generating

```bash
# Check permissions
ls -la reports/
chmod 777 reports/

# Check disk space
df -h

# View audit tool logs
docker compose logs audit-tool

# Run audit manually with verbose output
docker compose exec audit-tool python rancher_security_audit.py \
  --config /app/config.yaml \
  --full-scan \
  --format text
```

### Container Keeps Restarting

```bash
# Check container status
docker compose ps

# View recent logs
docker compose logs --tail=100 audit-tool

# Check for configuration errors
docker compose exec audit-tool cat /app/config.yaml

# Validate Python dependencies
docker compose exec audit-tool pip list
```

## 🎛️ Advanced Configurations

### Custom Rancher Configuration

Create `rancher-config.yaml`:

```yaml
# Custom Rancher settings
settings:
  server-url: "https://localhost:8443"
  telemetry-opt: "out"
```

Mount in `docker-compose.yml`:

```yaml
rancher:
  volumes:
    - ./rancher-config.yaml:/etc/rancher/config.yaml:ro
```

### Adding Custom Certificates

```bash
# Create certificates directory
mkdir -p certs

# Add your certificates
cp your-cert.pem certs/tls.crt
cp your-key.pem certs/tls.key

# Update docker-compose.yml
# Add to rancher service:
volumes:
  - ./certs:/etc/rancher/ssl:ro
environment:
  - CATTLE_SERVER_URL=https://your-domain.com
```

### Multi-Cluster Setup

To audit multiple Rancher instances:

```yaml
# docker-compose.multi.yml
services:
  rancher-prod:
    image: rancher/rancher:v2.8.0
    ports:
      - "8443:443"
    volumes:
      - rancher-prod-data:/var/lib/rancher

  rancher-staging:
    image: rancher/rancher:v2.8.0
    ports:
      - "9443:443"
    volumes:
      - rancher-staging-data:/var/lib/rancher

  audit-tool:
    build: .
    volumes:
      - ./config-multi.yaml:/app/config.yaml:ro
      - ./reports:/reports
```

Create `config-multi.yaml`:

```yaml
# Audit multiple Rancher instances
rancher_instances:
  - name: production
    url: https://rancher-prod:443
    access_key: ${RANCHER_PROD_ACCESS_KEY}
    secret_key: ${RANCHER_PROD_SECRET_KEY}
  
  - name: staging
    url: https://rancher-staging:443
    access_key: ${RANCHER_STAGING_ACCESS_KEY}
    secret_key: ${RANCHER_STAGING_SECRET_KEY}
```

### Persistent Logging

```yaml
# Add to docker-compose.yml
services:
  audit-tool:
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"
```

### Automated Report Cleanup

```bash
# Add to crontab in audit-tool
# Clean up reports older than 30 days
0 3 * * * find /reports -type f -mtime +30 -delete
```

### Integration with External Systems

**Send reports to Slack:**

```bash
# Add to .env
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/YOUR/WEBHOOK/URL

# Add to run-audit.sh
if [ -f /reports/latest-audit.html ]; then
  curl -X POST -H 'Content-type: application/json' \
    --data '{"text":"Security audit completed"}' \
    $SLACK_WEBHOOK_URL
fi
```

**Send reports via email:**

```python
# Add to rancher_security_audit.py
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders

def send_email_report(report_path):
    msg = MIMEMultipart()
    msg['From'] = os.getenv('EMAIL_FROM')
    msg['To'] = os.getenv('EMAIL_TO')
    msg['Subject'] = f'Rancher Security Audit - {datetime.now().strftime("%Y-%m-%d")}'
    
    with open(report_path, 'rb') as f:
        part = MIMEBase('application', 'octet-stream')
        part.set_payload(f.read())
        encoders.encode_base64(part)
        part.add_header('Content-Disposition', f'attachment; filename={os.path.basename(report_path)}')
        msg.attach(part)
    
    server = smtplib.SMTP(os.getenv('SMTP_SERVER'), os.getenv('SMTP_PORT'))
    server.starttls()
    server.login(os.getenv('SMTP_USER'), os.getenv('SMTP_PASS'))
    server.send_message(msg)
    server.quit()
```

## 📊 Monitoring and Maintenance

### Health Checks

```bash
# Check service health
docker compose ps

# Rancher health endpoint
curl -k https://localhost:8443/healthz

# Audit tool health
docker compose exec audit-tool python -c "import sys; sys.exit(0)"
```

### Resource Usage

```bash
# Monitor resource usage
docker stats rancher audit-tool

# Check disk usage
docker system df

# Clean up old data
docker system prune -a --volumes
```

### Backup and Restore

**Backup Rancher data:**

```bash
# Create backup
docker compose exec rancher rancher-backup create backup-$(date +%Y%m%d)

# Copy backup to host
docker cp rancher:/var/lib/rancher/management-state/backups/ ./backups/

# Or backup the volume
docker run --rm -v rancher-data:/data -v $(pwd)/backups:/backup \
  alpine tar czf /backup/rancher-backup-$(date +%Y%m%d).tar.gz -C /data .
```

**Restore from backup:**

```bash
# Stop services
docker compose down

# Restore volume
docker run --rm -v rancher-data:/data -v $(pwd)/backups:/backup \
  alpine tar xzf /backup/rancher-backup-YYYYMMDD.tar.gz -C /data

# Start services
docker compose up -d
```

### Updating Components

**Update Rancher:**

```bash
# Change version in .env
RANCHER_VERSION=v2.8.1

# Pull new image
docker compose pull rancher

# Recreate container
docker compose up -d rancher
```

**Update Audit Tool:**

```bash
# Rebuild audit tool image
docker compose build --no-cache audit-tool

# Restart with new image
docker compose up -d audit-tool
```

## 🔐 Security Best Practices

1. **Change default passwords immediately**
1. **Use strong API keys with expiration**
1. **Enable RBAC and least privilege**
1. **Regularly rotate credentials**
1. **Monitor audit logs**
1. **Keep Rancher and Docker updated**
1. **Restrict network access**
1. **Use TLS certificates from trusted CA**

## 📚 Additional Resources

- [Rancher Documentation](https://ranchermanager.docs.rancher.com/)
- [Docker Compose Documentation](https://docs.docker.com/compose/)
- [Rancher Security Best Practices](https://ranchermanager.docs.rancher.com/reference-guides/rancher-security)
- [CIS Kubernetes Benchmark](https://www.cisecurity.org/benchmark/kubernetes)

## 🤝 Contributing

Found an issue or have an improvement? Please open an issue or pull request!

## 📄 License

MIT License - See LICENSE file for details

-----

**Need Help?** Open an issue on GitHub or consult the <QUICKSTART.md> guide.
