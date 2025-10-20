#!/bin/bash

# ========================================

# Rancher Security Audit - Execution Script

# ========================================

# This script runs the security audit and handles report generation

set -e

# ––––––––––––––––––––

# Configuration

# ––––––––––––––––––––

SCRIPT_DIR=”$(cd “$(dirname “${BASH_SOURCE[0]}”)” && pwd)”
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
REPORT_DIR=”/reports”
LOG_DIR=”/app/logs”
CONFIG_FILE=”/app/config.yaml”

REPORT_FORMAT=”${REPORT_FORMAT:-html}”
REPORT_FILENAME=“audit-${TIMESTAMP}.${REPORT_FORMAT}”
REPORT_PATH=”${REPORT_DIR}/${REPORT_FILENAME}”

# ––––––––––––––––––––

# Logging

# ––––––––––––––––––––

LOG_FILE=”${LOG_DIR}/audit-${TIMESTAMP}.log”

log() {
echo “[$(date +’%Y-%m-%d %H:%M:%S’)] $*” | tee -a “$LOG_FILE”
}

log_error() {
echo “[$(date +’%Y-%m-%d %H:%M:%S’)] ERROR: $*” | tee -a “$LOG_FILE” >&2
}

# ––––––––––––––––––––

# Pre-flight Checks

# ––––––––––––––––––––

log “==========================================”
log “Starting Rancher Security Audit”
log “==========================================”

# Check if config file exists

if [ ! -f “$CONFIG_FILE” ]; then
log_error “Configuration file not found: $CONFIG_FILE”
exit 1
fi

# Check if Python is available

if ! command -v python &> /dev/null; then
log_error “Python is not installed or not in PATH”
exit 1
fi

# Check if audit script exists

if [ ! -f “${SCRIPT_DIR}/rancher_security_audit.py” ]; then
log_error “Audit script not found: ${SCRIPT_DIR}/rancher_security_audit.py”
exit 1
fi

# Create reports directory if it doesn’t exist

mkdir -p “$REPORT_DIR”
mkdir -p “$LOG_DIR”

# ––––––––––––––––––––

# Check Rancher Availability

# ––––––––––––––––––––

log “Checking Rancher availability…”

if curl -k -s -f “${RANCHER_URL:-https://rancher:443}/healthz” > /dev/null 2>&1; then
log “✓ Rancher is available”
else
log_error “Rancher is not available at ${RANCHER_URL:-https://rancher:443}”
log_error “Skipping audit run”
exit 1
fi

# ––––––––––––––––––––

# Run Security Audit

# ––––––––––––––––––––

log “Running security audit…”
log “Report format: ${REPORT_FORMAT}”
log “Output file: ${REPORT_PATH}”

START_TIME=$(date +%s)

if python “${SCRIPT_DIR}/rancher_security_audit.py”   
–config “$CONFIG_FILE”   
–full-scan   
–format “$REPORT_FORMAT”   
–output “$REPORT_PATH” >> “$LOG_FILE” 2>&1; then

```
END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))

log "✓ Security audit completed successfully"
log "Duration: ${DURATION} seconds"
log "Report saved to: ${REPORT_PATH}"

AUDIT_SUCCESS=true
```

else
END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))

```
log_error "Security audit failed"
log "Duration: ${DURATION} seconds"
log "Check log file for details: ${LOG_FILE}"

AUDIT_SUCCESS=false
```

fi

# ––––––––––––––––––––

# Create ‘latest’ symlink

# ––––––––––––––––––––

if [ “$AUDIT_SUCCESS” = true ]; then
LATEST_LINK=”${REPORT_DIR}/latest-audit.${REPORT_FORMAT}”
ln -sf “$REPORT_FILENAME” “$LATEST_LINK”
log “✓ Updated latest report symlink”
fi

# ––––––––––––––––––––

# Parse Report for Summary

# ––––––––––––––––––––

if [ “$AUDIT_SUCCESS” = true ] && [ -f “$REPORT_PATH” ]; then
log “”
log “Audit Summary:”
log “––––––––––––––––––––”

```
case "$REPORT_FORMAT" in
    json)
        # Parse JSON for counts
        if command -v jq &> /dev/null; then
            CRITICAL=$(jq -r '.critical | length' "$REPORT_PATH")
            HIGH=$(jq -r '.high | length' "$REPORT_PATH")
            MEDIUM=$(jq -r '.medium | length' "$REPORT_PATH")
            LOW=$(jq -r '.low | length' "$REPORT_PATH")
            
            log "  CRITICAL: $CRITICAL"
            log "  HIGH:     $HIGH"
            log "  MEDIUM:   $MEDIUM"
            log "  LOW:      $LOW"
        else
            log "  (Install jq to see summary)"
        fi
        ;;
    html)
        # Parse HTML for counts (basic grep)
        CRITICAL=$(grep -o "CRITICAL:[[:space:]]*[0-9]*" "$REPORT_PATH" | grep -o "[0-9]*" || echo "?")
        HIGH=$(grep -o "HIGH:[[:space:]]*[0-9]*" "$REPORT_PATH" | grep -o "[0-9]*" || echo "?")
        MEDIUM=$(grep -o "MEDIUM:[[:space:]]*[0-9]*" "$REPORT_PATH" | grep -o "[0-9]*" || echo "?")
        LOW=$(grep -o "LOW:[[:space:]]*[0-9]*" "$REPORT_PATH" | grep -o "[0-9]*" || echo "?")
        
        log "  CRITICAL: $CRITICAL"
        log "  HIGH:     $HIGH"
        log "  MEDIUM:   $MEDIUM"
        log "  LOW:      $LOW"
        ;;
    text)
        # Extract summary from text report
        grep -A 4 "FINDINGS SUMMARY:" "$REPORT_PATH" | tail -n 4 >> "$LOG_FILE"
        ;;
esac

log "----------------------------------------"
```

fi

# ––––––––––––––––––––

# Send Notifications

# ––––––––––––––––––––

if [ “$AUDIT_SUCCESS” = true ]; then
# Slack notification
if [ -n “$SLACK_WEBHOOK_URL” ]; then
log “Sending Slack notification…”

```
    SLACK_MESSAGE="Security audit completed for Rancher at ${RANCHER_URL}
```

Report: ${REPORT_FILENAME}
Critical: ${CRITICAL:-N/A} | High: ${HIGH:-N/A} | Medium: ${MEDIUM:-N/A} | Low: ${LOW:-N/A}”

```
    curl -X POST -H 'Content-type: application/json' \
        --data "{\"text\":\"${SLACK_MESSAGE}\"}" \
        "$SLACK_WEBHOOK_URL" &> /dev/null && log "✓ Slack notification sent" || log_error "Failed to send Slack notification"
fi

# Email notification
if [ "${EMAIL_ENABLED:-false}" = "true" ] && [ -n "$EMAIL_TO" ]; then
    log "Email notifications not yet implemented"
    # TODO: Implement email sending
fi
```

fi

# ––––––––––––––––––––

# Cleanup Old Reports

# ––––––––––––––––––––

if [ -n “$REPORT_RETENTION_DAYS” ] && [ “$REPORT_RETENTION_DAYS” -gt 0 ]; then
log “”
log “Cleaning up reports older than ${REPORT_RETENTION_DAYS} days…”

```
OLD_REPORTS=$(find "$REPORT_DIR" -type f -name "audit-*" -mtime +"$REPORT_RETENTION_DAYS" | wc -l)

if [ "$OLD_REPORTS" -gt 0 ]; then
    find "$REPORT_DIR" -type f -name "audit-*" -mtime +"$REPORT_RETENTION_DAYS" -delete
    log "✓ Deleted $OLD_REPORTS old report(s)"
else
    log "No old reports to clean up"
fi
```

fi

# ––––––––––––––––––––

# Cleanup Old Logs

# ––––––––––––––––––––

# Keep logs for same retention period as reports

if [ -n “$REPORT_RETENTION_DAYS” ] && [ “$REPORT_RETENTION_DAYS” -gt 0 ]; then
OLD_LOGS=$(find “$LOG_DIR” -type f -name “audit-*.log” -mtime +”$REPORT_RETENTION_DAYS” | wc -l)

```
if [ "$OLD_LOGS" -gt 0 ]; then
    find "$LOG_DIR" -type f -name "audit-*.log" -mtime +"$REPORT_RETENTION_DAYS" -delete
    log "✓ Deleted $OLD_LOGS old log file(s)"
fi
```

fi

# ––––––––––––––––––––

# Exit Status

# ––––––––––––––––––––

log “”
log “==========================================”
if [ “$AUDIT_SUCCESS” = true ]; then
log “Audit completed successfully”
log “==========================================”
exit 0
else
log “Audit completed with errors”
log “==========================================”
exit 1
fi
