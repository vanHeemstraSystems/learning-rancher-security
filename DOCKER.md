# Docker Deployment Guide

Comprehensive guide for deploying and managing the Rancher Security Audit Tool using Docker.

## 📋 Table of Contents

- [Overview](#overview)
- [Prerequisites](#prerequisites)
- [File Structure](#file-structure)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [Container Architecture](#container-architecture)
- [Makefile Commands](#makefile-commands)
- [Manual Docker Commands](#manual-docker-commands)
- [Troubleshooting](#troubleshooting)
- [Best Practices](#best-practices)

## 🎯 Overview

This Docker setup provides a complete, isolated environment for:

- **Rancher Server**: Running in a container for testing and learning
- **Audit Tool**: Containerized Python application for security scanning
- **Automated Scanning**: Scheduled security audits via cron
- **Report Generation**: Persistent storage of audit reports

**Environment Type**: Testing/Learning (not production-ready)

## 📦 Prerequisites

### Required Software

```bash
# Docker Engine 20.10+
docker --version
# Docker version 20.10.x

# Docker Compose V2+
docker compose version
# Docker Compose version v2.x.x

# Make (optional, but recommended)
make --version
```

### System Requirements

|Resource|Minimum                        |Recommended|
|--------|-------------------------------|-----------|
|CPU     |2 cores                        |4 cores    |
|RAM     |4 GB                           |8 GB       |
|Disk    |10 GB                          |20 GB      |
|OS      |Linux, macOS, Windows with WSL2|Linux      |

### Installation Links

- Docker: https://docs.docker.com/get-docker/
- Docker Compose: https://docs.docker.com/compose/install/
- Make: Usually pre-installed on Linux/macOS, Windows users can use WSL2

## 📁 File Structure

```
Learning-Rancher-Security/
├── docker-compose.yml          # Main orchestration file
├── docker-compose.dev.yml      # Development overrides
├── Dockerfile                  # Audit tool container definition
├── .dockerignore              # Files to exclude from build
├── docker-entrypoint.sh       # Container startup script
├── run-audit.sh               # Audit execution script
├── Makefile                   # Convenience commands
├── .env.example               # Environment template
├── .env                       # Your configuration (gitignored)
├── .gitignore                 # Git exclusions
├── rancher_security_audit.py  # Main audit tool
├── requirements.txt           # Python dependencies
├── config.yaml                # Auto-generated config
├── reports/                   # Audit reports (volume mount)
├── logs/                      # Application logs (volume mount)
└── backups/                   # Rancher backups (volume mount)
```

## 🚀 Quick Start

### Using Makefile (Recommended)

```bash
# 1. Initial setup
make setup

# 2. Edit configuration
nano .env

# 3. Start services
make start

# 4. Check status
make status

# 5. Get Rancher password
make password

# 6. Run first audit (after configuring API keys)
make audit

# 7. View report
make report
```

### Manual Setup

```bash
# 1. Clone and prepare
git clone https://github.com/yourusername/Learning-Rancher-Security.git
cd Learning-Rancher-Security
mkdir -p reports logs backups

# 2. Configure environment
cp .env.example .env
nano .env  # Edit with your settings

# 3. Start services
docker compose up -d

# 4. View logs
docker compose logs -f

# 5. Get bootstrap password
docker compose exec rancher cat /var/lib/rancher/server/bootstrap-secret

# 6. Access Rancher UI
open https://localhost:8443

# 7. Generate API credentials in Rancher UI
# Update .env with credentials

# 8. Restart audit tool
docker compose restart audit-tool

# 9. Run audit
docker compose exec audit-tool /app/run-audit.sh
```

## ⚙️ Configuration

### Environment Variables (.env)

```bash
# Rancher Configuration
RANCHER_VERSION=v2.8.0              # Rancher version
RANCHER_HTTP_PORT=8080              # HTTP port
RANCHER_HTTPS_PORT=8443             # HTTPS port
RANCHER_HOSTNAME=localhost          # Hostname

# API Credentials (set after Rancher setup)
RANCHER_URL=https://rancher:443
RANCHER_ACCESS_KEY=token-xxxxx
RANCHER_SECRET_KEY=secret-xxxxx

# Security
VERIFY_SSL=false                    # SSL verification

# Scheduling
AUDIT_SCHEDULE=0 2 * * *           # Cron schedule

# Reports
REPORT_FORMAT=html                  # html, json, or text
REPORT_RETENTION_DAYS=30           # Cleanup old reports

# Timezone
TZ=UTC                             # Your timezone
```

### Cron Schedule Examples

```bash
# Every day at 2 AM
AUDIT_SCHEDULE=0 2 * * *

# Every 6 hours
AUDIT_SCHEDULE=0 */6 * * *

# Weekdays at 9 AM
AUDIT_SCHEDULE=0 9 * * 1-5

# Every Sunday at midnight
AUDIT_SCHEDULE=0 0 * * 0

# Twice daily (6 AM and 6 PM)
AUDIT_SCHEDULE=0 6,18 * * *
```

### Configuration File (config.yaml)

Auto-generated from environment variables:

```yaml
rancher:
  url: "https://rancher:443"
  access_key: "${RANCHER_ACCESS_KEY}"
  secret_key: "${RANCHER_SECRET_KEY}"

verify_ssl: false

audit:
  checks:
    - authentication
    - api_tokens
    - rbac
    - secrets
    - network_policies
    - pod_security
    - tls
    - audit_logging
    - image_security
    - backup
```

## 🏗️ Container Architecture

### Service: rancher

**Image**: `rancher/rancher:v2.8.0`

**Purpose**: Rancher management server for testing

**Ports**:

- 8080:80 (HTTP)
- 8443:443 (HTTPS)

**Volumes**:

- `rancher-data`: Persistent Rancher data
- `rancher-log`: Audit logs

**Health Check**:

```bash
curl -f -k https://localhost/healthz
```

### Service: audit-tool

**Image**: Custom-built from Dockerfile

**Purpose**: Security audit scanner

**Dependencies**: Waits for Rancher to be healthy

**Volumes**:

- `./reports:/reports` - Audit reports
- `./logs:/app/logs` - Application logs
- `./config.yaml:/app/config.yaml` - Configuration

**User**: Non-root (UID 1000)

**Health Check**:

```bash
python -c "import sys; sys.exit(0)"
```

### Network

**Name**: `rancher-security-network`

**Driver**: Bridge

**Subnet**: 172.20.0.0/16

Services communicate internally using service names:

- `rancher` → Rancher server
- `audit-tool` → Audit application

## 🔧 Makefile Commands

### Setup & Lifecycle

```bash
make setup          # Initial setup
make start          # Start services
make stop           # Stop services
make restart        # Restart services
make clean          # Remove everything
```

### Monitoring

```bash
make status         # Service status
make health         # Health checks
make logs           # All logs
make logs-rancher   # Rancher logs only
make logs-audit     # Audit tool logs only
```

### Security Auditing

```bash
make audit          # Full security audit
make audit-quick    # Quick checks
make report         # View latest report
make reports        # List all reports
```

### Maintenance

```bash
make shell          # Shell in audit tool
make shell-rancher  # Shell in Rancher
make backup         # Backup Rancher data
make restore        # Restore from backup
make update         # Update images
make test           # Test configuration
```

### Cleanup

```bash
make clean-reports  # Delete all reports
make clean          # Full cleanup
```

## 🔨 Manual Docker Commands

### Service Management

```bash
# Start services
docker compose up -d

# Stop services
docker compose stop

# Remove services
docker compose down

# Remove with volumes
docker compose down -v

# View status
docker compose ps

# View logs
docker compose logs -f [service]
```

### Image Management

```bash
# Pull images
docker compose pull

# Build audit tool
docker compose build audit-tool

# Rebuild without cache
docker compose build --no-cache audit-tool

# List images
docker images | grep rancher
```

### Container Operations

```bash
# Execute command in container
docker compose exec audit-tool [command]

# Interactive shell
docker compose exec audit-tool /bin/bash

# Run as root (if needed)
docker compose exec -u root audit-tool /bin/bash

# View container details
docker inspect rancher
```

### Volume Management

```bash
# List volumes
docker volume ls | grep rancher

# Inspect volume
docker volume inspect rancher-data

# Backup volume
docker run --rm -v rancher-data:/data -v $(pwd):/backup \
  alpine tar czf /backup/backup.tar.gz -C /data .

# Restore volume
docker run --rm -v rancher-data:/data -v $(pwd):/backup \
  alpine tar xzf /backup/backup.tar.gz -C /data

# Remove volumes
docker volume rm rancher-data rancher-log
```

### Network Operations

```bash
# List networks
docker network ls | grep rancher

# Inspect network
docker network inspect rancher-security-network

# Test connectivity
docker compose exec audit-tool ping rancher
docker compose exec audit-tool curl -k https://rancher/healthz
```

## 🔍 Troubleshooting

### Rancher Won’t Start

**Issue**: Container exits immediately

```bash
# Check logs
docker compose logs rancher

# Common causes:
# 1. Port conflict
sudo lsof -i :8443
# Kill conflicting process or change port

# 2. Permission issues
docker compose down -v
docker volume rm rancher-data
docker compose up -d

# 3. Memory issues
docker stats rancher
# Increase Docker memory limit
```

### Audit Tool Connection Failed

**Issue**: Can’t connect to Rancher API

```bash
# Verify Rancher is running
docker compose ps

# Test network connectivity
docker compose exec audit-tool ping -c 3 rancher

# Test API endpoint
docker compose exec audit-tool curl -k https://rancher/v3

# Check credentials
docker compose exec audit-tool env | grep RANCHER

# Verify config file
docker compose exec audit-tool cat /app/config.yaml
```

### Reports Not Generating

**Issue**: No reports in ./reports/

```bash
# Check permissions
ls -la reports/
chmod 777 reports/

# Check disk space
df -h

# Run audit manually
docker compose exec audit-tool python rancher_security_audit.py \
  --config /app/config.yaml --full-scan --format text

# View audit logs
docker compose logs audit-tool
tail -f logs/audit-*.log
```

### Cron Not Running

**Issue**: Scheduled scans not executing

```bash
# Check cron is running
docker compose exec audit-tool ps aux | grep cron

# View cron schedule
docker compose exec audit-tool crontab -l

# Check cron logs
docker compose exec audit-tool cat /app/logs/cron.log

# Test cron manually
docker compose exec audit-tool /app/run-audit.sh
```

### SSL Certificate Errors

**Issue**: SSL verification failed

```bash
# Temporary: Disable SSL verification
# In .env:
VERIFY_SSL=false

# Restart audit tool
docker compose restart audit-tool

# Production: Add proper certificates
mkdir -p certs
cp your-cert.pem certs/tls.crt
cp your-key.pem certs/tls.key

# Update docker-compose.yml to mount certs
```

### Container Keeps Restarting

**Issue**: Service in restart loop

```bash
# Check exit code
docker compose ps

# View recent logs
docker compose logs --tail=50 audit-tool

# Check resource usage
docker stats

# Inspect container
docker inspect audit-tool

# Try running interactively
docker compose run --rm audit-tool /bin/bash
```

## 🛡️ Best Practices

### Security

1. **Change Default Passwords**
   
   ```bash
   # Set in .env before first start
   CATTLE_BOOTSTRAP_PASSWORD=strong-password-here
   ```
1. **Rotate API Keys**
   
   ```bash
   # Regenerate in Rancher UI every 90 days
   # Update .env
   # Restart: make restart
   ```
1. **Use SSL in Production**
   
   ```bash
   VERIFY_SSL=true
   # Add valid certificates
   ```
1. **Restrict Access**
   
   ```bash
   # Use firewall rules
   # Limit port exposure
   # Use VPN for remote access
   ```

### Performance

1. **Resource Limits**
   
   ```yaml
   # Add to docker-compose.yml
   services:
     rancher:
       deploy:
         resources:
           limits:
             memory: 4G
             cpus: '2'
   ```
1. **Volume Management**
   
   ```bash
   # Regular cleanup
   make clean-reports
   
   # Monitor disk usage
   docker system df
   ```
1. **Log Rotation**
   
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

### Maintenance

1. **Regular Updates**
   
   ```bash
   # Weekly
   make update
   ```
1. **Backup Schedule**
   
   ```bash
   # Daily backups
   0 1 * * * cd /path/to/repo && make backup
   ```
1. **Health Monitoring**
   
   ```bash
   # Check health regularly
   make health
   ```

### Development

1. **Use Development Compose**
   
   ```bash
   docker compose -f docker-compose.yml -f docker-compose.dev.yml up
   ```
1. **Live Code Reloading**
   
   ```bash
   # Already configured in docker-compose.dev.yml
   # Edit Python files and they update in container
   ```
1. **Debug Mode**
   
   ```bash
   # Set in .env
   DEBUG=true
   ```

## 📚 Additional Resources

- [Docker Documentation](https://docs.docker.com/)
- [Docker Compose Reference](https://docs.docker.com/compose/compose-file/)
- [Rancher Documentation](https://ranchermanager.docs.rancher.com/)
- [Dockerfile Best Practices](https://docs.docker.com/develop/dev-best-practices/)

## 🆘 Getting Help

- Check logs: `make logs`
- Test config: `make test`
- Health check: `make health`
- GitHub Issues: Report bugs and ask questions
- Documentation: Read <README.md> and <QUICKSTART.md>

-----

**Note**: This Docker setup is designed for learning and testing. For production Rancher deployments, use Kubernetes-based installations with proper HA configuration.
