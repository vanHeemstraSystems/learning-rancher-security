#!/bin/bash
set -e

# ========================================

# Rancher Security Audit Tool - Docker Entrypoint

# ========================================

echo “==========================================”
echo “Rancher Security Audit Tool”
echo “==========================================”
echo “Starting container…”
echo “”

# ––––––––––––––––––––

# Validate Environment Variables

# ––––––––––––––––––––

validate_env() {
local missing_vars=()

```
if [ -z "$RANCHER_URL" ]; then
    missing_vars+=("RANCHER_URL")
fi

if [ -z "$RANCHER_ACCESS_KEY" ] || [ "$RANCHER_ACCESS_KEY" = "your-access-key" ]; then
    echo "⚠️  WARNING: RANCHER_ACCESS_KEY not set or using default value"
    echo "   Please generate API credentials in Rancher UI and update .env file"
    echo "   Audit scans will fail until credentials are configured."
    echo ""
fi

if [ -z "$RANCHER_SECRET_KEY" ] || [ "$RANCHER_SECRET_KEY" = "your-secret-key" ]; then
    echo "⚠️  WARNING: RANCHER_SECRET_KEY not set or using default value"
    echo "   Please generate API credentials in Rancher UI and update .env file"
    echo "   Audit scans will fail until credentials are configured."
    echo ""
fi

if [ ${#missing_vars[@]} -ne 0 ]; then
    echo "❌ ERROR: Required environment variables are missing:"
    printf '   - %s\n' "${missing_vars[@]}"
    echo ""
    echo "Please check your .env file and docker-compose.yml configuration."
    exit 1
fi
```

}

validate_env

# ––––––––––––––––––––

# Display Configuration

# ––––––––––––––––––––

echo “Configuration:”
echo “  Rancher URL: $RANCHER_URL”
echo “  Verify SSL: ${VERIFY_SSL:-true}”
echo “  Audit Schedule: ${AUDIT_SCHEDULE:-0 2 * * *}”
echo “  Report Format: ${REPORT_FORMAT:-html}”
echo “  Timezone: ${TZ:-UTC}”
echo “”

# ––––––––––––––––––––

# Generate config.yaml from environment

# ––––––––––––––––––––

echo “Generating configuration file…”

cat > /app/config.yaml << EOF

# Auto-generated configuration from environment variables

# Do not edit manually - changes will be overwritten

rancher:
url: “${RANCHER_URL}”
access_key: “${RANCHER_ACCESS_KEY}”
secret_key: “${RANCHER_SECRET_KEY}”

verify_ssl: ${VERIFY_SSL:-false}

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

report:
format: “${REPORT_FORMAT:-html}”
output_path: “/reports/”

thresholds:
critical: 0
high: 5
EOF

echo “✓ Configuration file generated”
echo “”

# ––––––––––––––––––––

# Wait for Rancher to be ready

# ––––––––––––––––––––

echo “Waiting for Rancher to be ready…”

MAX_RETRIES=30
RETRY_COUNT=0
RANCHER_READY=false

while [ $RETRY_COUNT -lt $MAX_RETRIES ]; do
if curl -k -s -f “${RANCHER_URL}/healthz” > /dev/null 2>&1; then
RANCHER_READY=true
echo “✓ Rancher is ready!”
echo “”
break
fi

```
RETRY_COUNT=$((RETRY_COUNT + 1))
echo "  Attempt $RETRY_COUNT/$MAX_RETRIES - Rancher not ready yet, waiting..."
sleep 10
```

done

if [ “$RANCHER_READY” = false ]; then
echo “⚠️  WARNING: Rancher did not become ready within timeout period”
echo “   The audit tool will continue, but scans may fail until Rancher is fully initialized”
echo “”
fi

# ––––––––––––––––––––

# Test API Connectivity

# ––––––––––––––––––––

if [ -n “$RANCHER_ACCESS_KEY” ] && [ “$RANCHER_ACCESS_KEY” != “your-access-key” ]; then
echo “Testing API connectivity…”

```
if python3 -c "
```

import requests
import sys
import os
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

url = os.getenv(‘RANCHER_URL’)
auth = (os.getenv(‘RANCHER_ACCESS_KEY’), os.getenv(‘RANCHER_SECRET_KEY’))
verify = os.getenv(‘VERIFY_SSL’, ‘false’).lower() == ‘true’

try:
response = requests.get(f’{url}/v3’, auth=auth, verify=verify, timeout=10)
if response.status_code == 200:
data = response.json()
print(f’✓ API connection successful!’)
print(f’  Rancher Version: {data.get("version", "unknown")}’)
sys.exit(0)
else:
print(f’❌ API returned status code: {response.status_code}’)
sys.exit(1)
except Exception as e:
print(f’❌ API connection failed: {e}’)
sys.exit(1)
“ 2>&1; then
echo “”
else
echo “⚠️  WARNING: API connectivity test failed”
echo “   Please verify your API credentials in the .env file”
echo “   Scheduled scans will continue to retry…”
echo “”
fi
else
echo “⚠️  Skipping API connectivity test - credentials not configured”
echo “”
fi

# ––––––––––––––––––––

# Set up cron for scheduled scans

# ––––––––––––––––––––

echo “Setting up scheduled scans…”

# Update cron schedule from environment variable

if [ -n “$AUDIT_SCHEDULE” ]; then
echo “${AUDIT_SCHEDULE} /app/run-audit.sh >> /app/logs/cron.log 2>&1” | crontab -
echo “✓ Cron schedule configured: $AUDIT_SCHEDULE”
else
echo “0 2 * * * /app/run-audit.sh >> /app/logs/cron.log 2>&1” | crontab -
echo “✓ Cron schedule configured: 0 2 * * * (default)”
fi

# Start cron in background

cron
echo “✓ Cron daemon started”
echo “”

# ––––––––––––––––––––

# Report Cleanup

# ––––––––––––––––––––

if [ -n “$REPORT_RETENTION_DAYS” ] && [ “$REPORT_RETENTION_DAYS” -gt 0 ]; then
echo “Setting up report cleanup…”
echo “  Old reports will be deleted after ${REPORT_RETENTION_DAYS} days”

```
# Add cleanup to cron
(crontab -l 2>/dev/null; echo "0 3 * * * find /reports -type f -mtime +${REPORT_RETENTION_DAYS} -delete") | crontab -
echo "✓ Cleanup schedule configured"
echo ""
```

fi

# ––––––––––––––––––––

# Initial Scan (Optional)

# ––––––––––––––––––––

if [ “${RUN_INITIAL_SCAN:-false}” = “true” ]; then
echo “Running initial security scan…”
/app/run-audit.sh
echo “”
fi

# ––––––––––––––––––––

# Ready

# ––––––––––––––––––––

echo “==========================================”
echo “✓ Audit Tool Ready”
echo “==========================================”
echo “”
echo “Scheduled scans: $AUDIT_SCHEDULE”
echo “Reports location: /reports/”
echo “Logs location: /app/logs/”
echo “”
echo “To run a manual scan:”
echo “  docker compose exec audit-tool /app/run-audit.sh”
echo “”
echo “To view logs:”
echo “  docker compose logs -f audit-tool”
echo “”
echo “Container will now keep running for scheduled scans…”
echo “==========================================”
echo “”

# ––––––––––––––––––––

# Execute CMD

# ––––––––––––––––––––

exec “$@”
