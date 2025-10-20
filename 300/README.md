# 300 - Learning Our Subject

# Learning Rancher Security

A comprehensive repository for learning and implementing security best practices in Rancher, the Kubernetes management platform.

## 🎯 Purpose

This repository serves as a learning resource and practical toolkit for cybersecurity engineers focusing on securing Rancher deployments. It includes security auditing tools, hardening guides, and hands-on examples.

## 🛠️ Main Tool: Rancher Security Audit Scanner

A Python-based security audit tool that analyzes Rancher deployments for common security misconfigurations and provides actionable recommendations.

### Features

- **Authentication & Authorization Auditing**: Validates RBAC configurations and user permissions
- **Secret Management Analysis**: Detects exposed secrets and weak encryption practices
- **Network Policy Verification**: Checks for proper network segmentation
- **Pod Security Standards**: Validates PSP/PSA enforcement
- **TLS/SSL Configuration**: Verifies certificate validity and encryption settings
- **API Security**: Checks for exposed APIs and authentication mechanisms
- **Compliance Checking**: Validates against CIS Kubernetes and Rancher benchmarks
- **Report Generation**: Creates detailed security assessment reports

## 📋 Prerequisites

- Python 3.8+
- Access to a Rancher instance (API endpoint and credentials)
- kubectl configured (for cluster-level checks)
- Basic understanding of Kubernetes and Rancher architecture

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/Learning-Rancher-Security.git
cd Learning-Rancher-Security

# Install dependencies
pip install -r requirements.txt

# Configure your Rancher credentials
cp config.example.yaml config.yaml
# Edit config.yaml with your Rancher details
```

### Usage

```bash
# Run a full security audit
python rancher_security_audit.py --config config.yaml --full-scan

# Run specific checks
python rancher_security_audit.py --config config.yaml --check authentication
python rancher_security_audit.py --config config.yaml --check secrets

# Generate HTML report
python rancher_security_audit.py --config config.yaml --output report.html
```

## 🔒 Security Topics Covered

### 1. Authentication & Access Control

- Local authentication vs. external providers (AD, LDAP, SAML, OAuth)
- Multi-factor authentication (MFA) enforcement
- API key rotation and management
- Service account security

### 2. RBAC (Role-Based Access Control)

- Global roles vs. cluster roles vs. project roles
- Principle of least privilege implementation
- Custom role creation and auditing
- Permission boundaries

### 3. Secrets Management

- Kubernetes secrets encryption at rest
- External secrets management integration (Vault, AWS Secrets Manager)
- Secret rotation policies
- Prevention of secrets in environment variables

### 4. Network Security

- Network policy enforcement
- Ingress/Egress rules
- Service mesh integration (Istio, Linkerd)
- Private registry configuration

### 5. Pod Security

- Pod Security Policies (PSP) - deprecated
- Pod Security Admission (PSA) - current standard
- Security contexts and capabilities
- Resource limits and quotas

### 6. TLS/SSL Configuration

- Certificate management
- Internal cluster communication encryption
- Ingress controller SSL termination
- Certificate rotation automation

### 7. Audit Logging

- Rancher audit log configuration
- Kubernetes audit policies
- Log aggregation and monitoring
- SIEM integration

### 8. Supply Chain Security

- Image scanning and vulnerability management
- Trusted registry enforcement
- Image signature verification
- Admission controllers (OPA, Kyverno)

## 📚 Learning Path

1. **Beginner**: Understand Rancher architecture and basic security concepts
1. **Intermediate**: Implement RBAC, network policies, and pod security standards
1. **Advanced**: Integrate external security tools, implement zero-trust, automate security scanning
1. **Expert**: Develop custom security policies, contribute to Rancher security, red team exercises

## 🔍 Example Scenarios

### Scenario 1: Detecting Exposed Secrets

The audit tool will flag:

- Secrets stored in ConfigMaps
- Environment variables containing sensitive data
- Unencrypted secrets at rest
- Hardcoded credentials in deployment manifests

### Scenario 2: RBAC Misconfiguration

Identifies:

- Overly permissive cluster-admin bindings
- Service accounts with excessive privileges
- Missing resource quotas in projects
- Wildcard permissions in roles

### Scenario 3: Network Policy Gaps

Detects:

- Namespaces without network policies
- Unrestricted ingress/egress rules
- Missing default-deny policies
- Exposed internal services

## 📊 Sample Report Output

```
=== RANCHER SECURITY AUDIT REPORT ===
Date: 2025-10-18
Rancher Version: v2.8.0
Clusters Scanned: 3

CRITICAL FINDINGS: 2
HIGH FINDINGS: 5
MEDIUM FINDINGS: 12
LOW FINDINGS: 8

[CRITICAL] Cluster 'production' has no pod security policies enforced
[CRITICAL] API tokens found with no expiration date

[HIGH] 15 secrets detected without encryption at rest
[HIGH] Cluster 'staging' allows privileged containers
...
```

## 🧪 Lab Environment Setup

Instructions for setting up a test Rancher environment for security practice:

```bash
# Deploy Rancher in Docker (testing only)
docker run -d --restart=unless-stopped \
  -p 80:80 -p 443:443 \
  --privileged \
  rancher/rancher:latest

# Or use Helm for production-like setup
helm repo add rancher-latest https://releases.rancher.com/server-charts/latest
kubectl create namespace cattle-system
helm install rancher rancher-latest/rancher \
  --namespace cattle-system \
  --set hostname=rancher.example.com
```

## 🤝 Contributing

Contributions are welcome! Areas for improvement:

- Additional security checks
- Integration with more security tools
- Enhanced reporting formats
- Documentation improvements

## 📖 Resources

- [Rancher Security Best Practices](https://ranchermanager.docs.rancher.com/reference-guides/rancher-security)
- [CIS Kubernetes Benchmark](https://www.cisecurity.org/benchmark/kubernetes)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [Kubernetes Security Documentation](https://kubernetes.io/docs/concepts/security/)

## ⚠️ Disclaimer

This tool is for educational and authorized security testing purposes only. Always obtain proper authorization before scanning any Rancher deployment. The author is not responsible for misuse of this tool.

## 📜 License

MIT License - See LICENSE file for details

## 👤 Author

Created as part of a cybersecurity learning journey focusing on container orchestration security.

-----

**Note**: This is a learning repository. Always test security tools in non-production environments first.

