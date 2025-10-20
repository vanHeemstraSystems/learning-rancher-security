# Quick Start Guide

Get started with the Rancher Security Audit Tool in minutes.

## Prerequisites

- Python 3.8 or higher
- Access to a Rancher instance
- Rancher API credentials (access key and secret key)

## Step-by-Step Setup

### 1. Clone the Repository

```bash
git clone https://github.com/yourusername/Learning-Rancher-Security.git
cd Learning-Rancher-Security
```

### 2. Install Dependencies

```bash
# Create a virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install required packages
pip install -r requirements.txt
```

### 3. Generate API Credentials in Rancher

1. Log into your Rancher UI
1. Click on your user profile (top-right corner)
1. Select **API & Keys**
1. Click **Add Key**
1. Give it a description (e.g., “Security Audit Tool”)
1. Set an expiration date (recommended: 90 days)
1. Click **Create**
1. **Save the credentials immediately** - they won’t be shown again!

### 4. Configure the Tool

```bash
# Copy the example configuration
cp config.example.yaml config.yaml

# Edit with your details
nano config.yaml  # or use your preferred editor
```

Update the configuration:

```yaml
rancher:
  url: "https://your-rancher-instance.com"
  access_key: "token-xxxxx"
  secret_key: "your-secret-key-here"
verify_ssl: true
```

**Important**: Never commit `config.yaml` to version control!

```bash
# Ensure it's in .gitignore
echo "config.yaml" >> .gitignore
```

### 5. Run Your First Scan

```bash
# Run a full security audit
python rancher_security_audit.py --config config.yaml --full-scan

# Output will be displayed in the terminal
```

## Common Usage Examples

### Generate an HTML Report

```bash
python rancher_security_audit.py \
  --config config.yaml \
  --full-scan \
  --format html \
  --output security-report.html

# Open the report in your browser
open security-report.html  # macOS
# or
xdg-open security-report.html  # Linux
# or
start security-report.html  # Windows
```

### Run Specific Security Checks

```bash
# Check only authentication configuration
python rancher_security_audit.py \
  --config config.yaml \
  --check authentication_config

# Check API token security
python rancher_security_audit.py \
  --config config.yaml \
  --check api_tokens

# Check RBAC configuration
python rancher_security_audit.py \
  --config config.yaml \
  --check rbac_configuration
```

Available checks:

- `authentication_config`
- `api_tokens`
- `rbac_configuration`
- `secrets_security`
- `network_policies`
- `pod_security`
- `tls_configuration`
- `audit_logging`
- `image_security`
- `backup_configuration`

### Generate JSON Output for Integration

```bash
python rancher_security_audit.py \
  --config config.yaml \
  --full-scan \
  --format json \
  --output results.json

# Use with jq for parsing
cat results.json | jq '.critical'
```

## Understanding the Output

### Severity Levels

- **CRITICAL**: Immediate action required - severe security risk
- **HIGH**: Important security issues that should be addressed soon
- **MEDIUM**: Security improvements recommended
- **LOW**: Minor security concerns or optimizations
- **INFO**: Informational findings for awareness

### Sample Output

```
=============================================================
RANCHER SECURITY AUDIT
=============================================================
Target: https://rancher.example.com
Started: 2025-10-18 14:30:00
=============================================================

[*] Checking authentication configuration...
[*] Checking API tokens...
[*] Checking RBAC configuration...
[*] Checking secrets security...
...

=============================================================
AUDIT COMPLETE
=============================================================

FINDINGS SUMMARY:
  CRITICAL: 2
  HIGH:     5
  MEDIUM:   8
  LOW:      3
  INFO:     4

=============================================================
CRITICAL FINDINGS
=============================================================

[CRITICAL-1] 3 API Tokens Without Expiration
Description: Found 3 API tokens that never expire...
Recommendation: Set expiration dates for all API tokens...

[CRITICAL-2] No Pod Security Policy Configured: production
Description: Cluster "production" has no default pod security...
Recommendation: Implement Pod Security Admission (PSA)...
```

## Troubleshooting

### Common Issues

**Issue**: `SSL Certificate Verification Failed`

```bash
# Temporary workaround for self-signed certificates (testing only!)
# Update config.yaml:
verify_ssl: false

# Better solution: Add your CA certificate
export REQUESTS_CA_BUNDLE=/path/to/ca-bundle.crt
```

**Issue**: `Authentication Failed (401)`

- Verify your API credentials are correct
- Check if the API key has expired
- Ensure you have sufficient permissions

**Issue**: `Connection Timeout`

- Check network connectivity to Rancher
- Verify firewall rules allow API access
- Check if Rancher is behind a VPN

**Issue**: `Permission Denied`

- Your API key needs read permissions for cluster resources
- Create a service account with appropriate RBAC roles

## Best Practices

### 1. Test Environment First

```bash
# Always test against non-production first
python rancher_security_audit.py \
  --config config-test.yaml \
  --full-scan
```

### 2. Regular Scans

Set up a cron job for regular audits:

```bash
# Run weekly security audit
0 2 * * 0 /path/to/venv/bin/python /path/to/rancher_security_audit.py \
  --config /path/to/config.yaml \
  --full-scan \
  --output /reports/audit-$(date +\%Y\%m\%d).html
```

### 3. Secure Your Configuration

```bash
# Encrypt config file
gpg --encrypt --recipient security@company.com config.yaml

# Use environment variables
export RANCHER_URL="https://rancher.example.com"
export RANCHER_ACCESS_KEY="token-xxxxx"
export RANCHER_SECRET_KEY="secret"

# Modify config.yaml to use env vars
rancher:
  url: "${RANCHER_URL}"
  access_key: "${RANCHER_ACCESS_KEY}"
  secret_key: "${RANCHER_SECRET_KEY}"
```

### 4. Review Findings

Don’t just run the tool - act on findings:

1. **Prioritize** by severity
1. **Document** current state
1. **Create tickets** for remediation
1. **Rerun scan** after fixes
1. **Track progress** over time

## Next Steps

1. **Review all findings** from your first scan
1. **Create a remediation plan** for critical and high findings
1. **Set up automated scans** (see GitHub Actions workflow)
1. **Integrate with your SIEM** using JSON output
1. **Customize checks** for your environment
1. **Contribute** improvements back to the project

## Learning Resources

- Read the full <README.md> for detailed documentation
- Check <SECURITY.md> for security best practices
- Review Rancher’s official [Security Guide](https://ranchermanager.docs.rancher.com/reference-guides/rancher-security)
- Study the [CIS Kubernetes Benchmark](https://www.cisecurity.org/benchmark/kubernetes)

## Getting Help

- GitHub Issues: For bugs and feature requests
- GitHub Discussions: For questions and community support
- Security Issues: Email security@example.com privately

## Example Workflow

Here’s a complete workflow from setup to remediation:

```bash
# 1. Initial setup
git clone https://github.com/yourusername/Learning-Rancher-Security.git
cd Learning-Rancher-Security
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cp config.example.yaml config.yaml
# Edit config.yaml with your credentials

# 2. First scan
python rancher_security_audit.py \
  --config config.yaml \
  --full-scan \
  --format html \
  --output baseline-audit.html

# 3. Review findings
open baseline-audit.html

# 4. Fix critical issues
# ... implement fixes in Rancher ...

# 5. Verify fixes
python rancher_security_audit.py \
  --config config.yaml \
  --check pod_security \
  --format text

# 6. Full rescan
python rancher_security_audit.py \
  --config config.yaml \
  --full-scan \
  --format html \
  --output post-remediation-audit.html

# 7. Compare results
diff baseline-audit.html post-remediation-audit.html
```

Happy auditing! 🔒
