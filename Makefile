# Makefile for Rancher Security Audit Tool

# Provides convenient commands for Docker-based deployment

.PHONY: help setup start stop restart logs clean audit report status shell health backup restore update

# Default target

.DEFAULT_GOAL := help

# Colors for output

BLUE := \033[0;34m
GREEN := \033[0;32m
YELLOW := \033[0;33m
RED := \033[0;31m
NC := \033[0m # No Color

## help: Display this help message

help:
@echo “$(BLUE)Rancher Security Audit Tool - Docker Commands$(NC)”
@echo “”
@echo “$(GREEN)Setup Commands:$(NC)”
@echo “  make setup          - Initial setup (create .env, directories)”
@echo “  make start          - Start Rancher and audit tool”
@echo “  make stop           - Stop all services”
@echo “  make restart        - Restart all services”
@echo “”
@echo “$(GREEN)Monitoring Commands:$(NC)”
@echo “  make logs           - View logs from all services”
@echo “  make logs-rancher   - View Rancher logs”
@echo “  make logs-audit     - View audit tool logs”
@echo “  make status         - Show service status”
@echo “  make health         - Check health of services”
@echo “”
@echo “$(GREEN)Audit Commands:$(NC)”
@echo “  make audit          - Run manual security audit”
@echo “  make audit-quick    - Run specific checks”
@echo “  make report         - View latest report”
@echo “  make reports        - List all reports”
@echo “”
@echo “$(GREEN)Maintenance Commands:$(NC)”
@echo “  make shell          - Open shell in audit tool container”
@echo “  make shell-rancher  - Open shell in Rancher container”
@echo “  make clean          - Remove containers and volumes”
@echo “  make clean-reports  - Delete all reports”
@echo “  make backup         - Backup Rancher data”
@echo “  make restore        - Restore Rancher data”
@echo “  make update         - Update images and restart”
@echo “”

## setup: Initial setup - create necessary files and directories

setup:
@echo “$(BLUE)Setting up Rancher Security Audit environment…$(NC)”
@mkdir -p reports logs backups
@if [ ! -f .env ]; then   
cp .env.example .env;   
echo “$(GREEN)✓ Created .env file from template$(NC)”;   
echo “$(YELLOW)⚠ Please edit .env with your configuration$(NC)”;   
else   
echo “$(YELLOW)⚠ .env file already exists, skipping$(NC)”;   
fi
@chmod +x docker-entrypoint.sh run-audit.sh
@echo “$(GREEN)✓ Setup complete!$(NC)”
@echo “”
@echo “$(YELLOW)Next steps:$(NC)”
@echo “1. Edit .env file with your configuration”
@echo “2. Run ‘make start’ to start services”
@echo “3. Access Rancher at https://localhost:8443”
@echo “4. Generate API credentials and update .env”
@echo “5. Run ‘make audit’ to test the audit tool”

## start: Start all services

start:
@echo “$(BLUE)Starting Rancher and Audit Tool…$(NC)”
@docker compose up -d
@echo “$(GREEN)✓ Services started$(NC)”
@echo “”
@echo “$(YELLOW)Rancher UI:$(NC) https://localhost:8443”
@echo “$(YELLOW)Bootstrap password:$(NC) Run ‘make password’ to retrieve”
@echo “”
@echo “Waiting for services to be healthy…”
@sleep 5
@make status

## stop: Stop all services

stop:
@echo “$(BLUE)Stopping services…$(NC)”
@docker compose stop
@echo “$(GREEN)✓ Services stopped$(NC)”

## restart: Restart all services

restart:
@echo “$(BLUE)Restarting services…$(NC)”
@docker compose restart
@echo “$(GREEN)✓ Services restarted$(NC)”
@make status

## logs: View logs from all services

logs:
@docker compose logs -f

## logs-rancher: View Rancher logs only

logs-rancher:
@docker compose logs -f rancher

## logs-audit: View audit tool logs only

logs-audit:
@docker compose logs -f audit-tool

## status: Show status of all services

status:
@echo “$(BLUE)Service Status:$(NC)”
@docker compose ps
@echo “”
@echo “$(BLUE)Resource Usage:$(NC)”
@docker stats –no-stream rancher audit-tool

## health: Check health of services

health:
@echo “$(BLUE)Checking service health…$(NC)”
@echo “”
@echo “$(YELLOW)Rancher:$(NC)”
@if docker compose exec rancher curl -k -f -s https://localhost/healthz > /dev/null 2>&1; then   
echo “  $(GREEN)✓ Healthy$(NC)”;   
else   
echo “  $(RED)✗ Unhealthy$(NC)”;   
fi
@echo “”
@echo “$(YELLOW)Audit Tool:$(NC)”
@if docker compose exec audit-tool python -c “import sys; sys.exit(0)” > /dev/null 2>&1; then   
echo “  $(GREEN)✓ Healthy$(NC)”;   
else   
echo “  $(RED)✗ Unhealthy$(NC)”;   
fi

## password: Retrieve Rancher bootstrap password

password:
@echo “$(BLUE)Rancher Bootstrap Password:$(NC)”
@docker compose exec rancher cat /var/lib/rancher/server/bootstrap-secret 2>/dev/null || echo “$(RED)Error: Could not retrieve password$(NC)”

## audit: Run manual security audit

audit:
@echo “$(BLUE)Running security audit…$(NC)”
@docker compose exec audit-tool /app/run-audit.sh
@echo “”
@echo “$(GREEN)✓ Audit complete$(NC)”
@echo “$(YELLOW)View report:$(NC) make report”

## audit-quick: Run quick audit (specific checks only)

audit-quick:
@echo “$(BLUE)Running quick security checks…$(NC)”
@docker compose exec audit-tool python rancher_security_audit.py   
–config /app/config.yaml   
–check authentication_config
@docker compose exec audit-tool python rancher_security_audit.py   
–config /app/config.yaml   
–check api_tokens

## report: View the latest audit report

report:
@echo “$(BLUE)Opening latest audit report…$(NC)”
@if [ -f reports/latest-audit.html ]; then   
open reports/latest-audit.html 2>/dev/null ||   
xdg-open reports/latest-audit.html 2>/dev/null ||   
start reports/latest-audit.html 2>/dev/null ||   
echo “$(YELLOW)Report location: reports/latest-audit.html$(NC)”;   
else   
echo “$(RED)No report found. Run ‘make audit’ first.$(NC)”;   
fi

## reports: List all available reports

reports:
@echo “$(BLUE)Available Reports:$(NC)”
@ls -lh reports/ 2>/dev/null || echo “$(YELLOW)No reports found$(NC)”

## shell: Open interactive shell in audit tool container

shell:
@echo “$(BLUE)Opening shell in audit tool container…$(NC)”
@docker compose exec audit-tool /bin/bash

## shell-rancher: Open interactive shell in Rancher container

shell-rancher:
@echo “$(BLUE)Opening shell in Rancher container…$(NC)”
@docker compose exec rancher /bin/bash

## clean: Remove all containers, volumes, and networks

clean:
@echo “$(YELLOW)⚠ This will remove all containers, volumes, and data!$(NC)”
@read -p “Are you sure? [y/N] “ -n 1 -r;   
echo;   
if [[ $$REPLY =~ ^[Yy]$$ ]]; then   
echo “$(BLUE)Cleaning up…$(NC)”;   
docker compose down -v;   
echo “$(GREEN)✓ Cleanup complete$(NC)”;   
else   
echo “$(YELLOW)Cleanup cancelled$(NC)”;   
fi

## clean-reports: Delete all audit reports

clean-reports:
@echo “$(YELLOW)⚠ This will delete all audit reports!$(NC)”
@read -p “Are you sure? [y/N] “ -n 1 -r;   
echo;   
if [[ $$REPLY =~ ^[Yy]$$ ]]; then   
rm -rf reports/*;   
echo “$(GREEN)✓ Reports deleted$(NC)”;   
else   
echo “$(YELLOW)Deletion cancelled$(NC)”;   
fi

## backup: Backup Rancher data

backup:
@echo “$(BLUE)Creating backup…$(NC)”
@mkdir -p backups
@docker run –rm -v rancher-data:/data -v $$(pwd)/backups:/backup   
alpine tar czf /backup/rancher-backup-$$(date +%Y%m%d-%H%M%S).tar.gz -C /data .
@echo “$(GREEN)✓ Backup created in backups/$(NC)”

## restore: Restore Rancher data from backup

restore:
@echo “$(BLUE)Available backups:$(NC)”
@ls -lh backups/*.tar.gz 2>/dev/null || echo “$(YELLOW)No backups found$(NC)”
@echo “”
@read -p “Enter backup filename to restore: “ backup;   
if [ -f “backups/$$backup” ]; then   
echo “$(YELLOW)⚠ This will overwrite current Rancher data!$(NC)”;   
read -p “Continue? [y/N] “ -n 1 -r;   
echo;   
if [[ $$REPLY =~ ^[Yy]$$ ]]; then   
docker compose down;   
docker run –rm -v rancher-data:/data -v $$(pwd)/backups:/backup   
alpine tar xzf /backup/$$backup -C /data;   
docker compose up -d;   
echo “$(GREEN)✓ Restore complete$(NC)”;   
fi   
else   
echo “$(RED)Backup file not found$(NC)”;   
fi

## update: Pull latest images and restart services

update:
@echo “$(BLUE)Updating images…$(NC)”
@docker compose pull
@docker compose build –no-cache audit-tool
@docker compose up -d
@echo “$(GREEN)✓ Update complete$(NC)”
@make status

## test: Test the audit tool configuration

test:
@echo “$(BLUE)Testing audit tool configuration…$(NC)”
@docker compose exec audit-tool python -c “  
import requests, os, sys, urllib3;   
urllib3.disable_warnings();   
url = os.getenv(‘RANCHER_URL’);   
auth = (os.getenv(‘RANCHER_ACCESS_KEY’), os.getenv(‘RANCHER_SECRET_KEY’));   
try:   
r = requests.get(f’{url}/v3’, auth=auth, verify=False, timeout=10);   
if r.status_code == 200:   
print(’$(GREEN)✓ Configuration is valid$(NC)’);   
print(f’  Rancher Version: {r.json().get("version")}’);   
sys.exit(0);   
else:   
print(’$(RED)✗ Authentication failed$(NC)’);   
sys.exit(1);   
except Exception as e:   
print(f’$(RED)✗ Connection failed: {e}$(NC)’);   
sys.exit(1)”

## ps: Alias for status

ps: status
