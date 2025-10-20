# Security Policy

## Purpose

This repository contains security auditing tools for Rancher deployments. As a security-focused project, we take the security of this codebase seriously.

## Supported Versions

|Version|Supported         |
|-------|------------------|
|1.x.x  |:white_check_mark:|
|< 1.0  |:x:               |

## Reporting a Vulnerability

If you discover a security vulnerability in this tool, please follow these steps:

### For Tool Vulnerabilities

1. **Do NOT** open a public GitHub issue
1. Email the maintainer directly at [your-email@example.com]
1. Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

### Response Timeline

- **Initial Response**: Within 48 hours
- **Status Update**: Within 7 days
- **Fix Timeline**: Depends on severity
  - Critical: 24-48 hours
  - High: 1 week
  - Medium: 2 weeks
  - Low: Next release cycle

## Security Considerations When Using This Tool

### Authentication Credentials

- **NEVER** commit `config.yaml` with real credentials to version control
- Use environment variables or secrets management for CI/CD
- Rotate API keys regularly
- Use read-only API keys when possible

### Running in Production

- Always review the code before running against production systems
- Test in non-production environments first
- Ensure you have proper authorization before scanning
- Be aware that API calls may trigger audit logs
- Some checks may impact performance during scan

### Data Handling

This tool:

- ✅ Only reads configuration data
- ✅ Does not modify any Rancher settings
- ✅ Does not store credentials permanently
- ✅ Generates reports that may contain sensitive information
  - Keep reports secure
  - Do not commit reports to public repositories
  - Sanitize reports before sharing

### Network Security

- Use VPN or secure network when connecting to Rancher
- Verify SSL certificates in production (set `verify_ssl: true`)
- Only disable SSL verification in isolated test environments
- Be cautious when running from untrusted networks

## Secure Usage Best Practices

### 1. Credential Management

```yaml
# GOOD - Using environment variables
rancher:
  url: "${RANCHER_URL}"
  access_key: "${RANCHER_ACCESS_KEY}"
  secret_key: "${RANCHER_SECRET_KEY}"

# BAD - Hardcoded credentials
rancher:
  url: "https://rancher.example.com"
  access_key: "token-abc123"
  secret_key: "secret-xyz789"
```

### 2. Least Privilege

Create a dedicated service account with minimal permissions:

- Read-only access to cluster resources
- No write/delete permissions
- Limited to necessary namespaces

### 3. Audit Logging

- Enable audit logging in Rancher before running scans
- Monitor for unusual API activity
- Review scan activities in audit logs

### 4. Report Security

```bash
# Encrypt reports containing sensitive data
gpg --encrypt --recipient security@company.com report.html

# Use secure channels for sharing
# - Encrypted email
# - Secure file sharing platforms
# - Internal security portals
```

## Known Limitations

### False Positives

The tool may generate false positives in certain scenarios:

- Custom security implementations not recognized
- Organization-specific security controls
- Edge cases in configuration detection

Always validate findings manually before taking action.

### Coverage Gaps

This tool does not check:

- Application-level security within workloads
- Runtime security events
- Image vulnerabilities (use dedicated image scanners)
- Supply chain security beyond basic checks

### Performance Impact

- Large Rancher deployments may take longer to scan
- API rate limits may affect scan completion
- Network latency can impact scan duration

## Responsible Disclosure

If you use this tool to discover vulnerabilities in your Rancher deployment:

1. **Document findings** thoroughly
1. **Assess risk** and prioritize remediation
1. **Fix issues** before publicizing
1. **Follow your organization’s** security incident response procedures
1. **Update security documentation** after remediation

## Legal and Ethical Use

### Authorized Use Only

- Only scan systems you own or have explicit permission to test
- Follow your organization’s security testing policies
- Comply with applicable laws and regulations
- Respect responsible disclosure practices

### Prohibited Use

Do NOT use this tool for:

- Unauthorized access to systems
- Malicious activities
- Compliance violations
- Disrupting services

## Dependencies Security

We regularly update dependencies to address security vulnerabilities:

```bash
# Check for vulnerable dependencies
pip install safety
safety check -r requirements.txt

# Update dependencies
pip install --upgrade -r requirements.txt
```

## Security Hardening Checklist

Before deploying this tool:

- [ ] Review and understand all code
- [ ] Use read-only API credentials
- [ ] Enable audit logging
- [ ] Test in non-production first
- [ ] Secure configuration files
- [ ] Encrypt sensitive reports
- [ ] Document authorized scan times
- [ ] Establish incident response plan
- [ ] Train team on proper usage
- [ ] Regular tool updates

## Contact

For security concerns:

- Email: [security-email@example.com]
- PGP Key: [Link to PGP key]

For general questions:

- GitHub Issues: [Only for non-sensitive topics]
- Discussions: [For community questions]

## Acknowledgments

We appreciate security researchers who responsibly disclose vulnerabilities. Contributors will be acknowledged in release notes (unless anonymity is requested).

-----

**Remember**: This tool is designed to help improve security. Use it responsibly and ethically.
