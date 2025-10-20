#!/usr/bin/env python3
“””
Rancher Security Audit Tool
A comprehensive security scanner for Rancher deployments
“””

import requests
import yaml
import json
import argparse
import sys
from datetime import datetime, timedelta
from typing import Dict, List, Tuple
from urllib3.exceptions import InsecureRequestWarning
import base64
import re

# Suppress SSL warnings for self-signed certificates (in testing only)

requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

class RancherSecurityAuditor:
“”“Main class for auditing Rancher security configurations”””

```
def __init__(self, rancher_url: str, access_key: str, secret_key: str, verify_ssl: bool = True):
    self.rancher_url = rancher_url.rstrip('/')
    self.auth = (access_key, secret_key)
    self.verify_ssl = verify_ssl
    self.findings = {
        'critical': [],
        'high': [],
        'medium': [],
        'low': [],
        'info': []
    }
    
def add_finding(self, severity: str, title: str, description: str, recommendation: str):
    """Add a security finding to the report"""
    finding = {
        'title': title,
        'description': description,
        'recommendation': recommendation,
        'timestamp': datetime.now().isoformat()
    }
    self.findings[severity].append(finding)

def api_request(self, endpoint: str) -> Dict:
    """Make an authenticated API request to Rancher"""
    url = f"{self.rancher_url}/v3/{endpoint}"
    try:
        response = requests.get(url, auth=self.auth, verify=self.verify_ssl, timeout=30)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"[ERROR] API request failed for {endpoint}: {e}")
        return {}

def check_authentication_config(self):
    """Audit authentication and access control configurations"""
    print("[*] Checking authentication configuration...")
    
    # Check auth config
    auth_configs = self.api_request('authconfigs')
    
    if auth_configs.get('data'):
        local_auth_enabled = False
        external_auth_enabled = False
        
        for config in auth_configs['data']:
            if config.get('type') == 'localConfig' and config.get('enabled'):
                local_auth_enabled = True
            elif config.get('enabled') and config.get('type') != 'localConfig':
                external_auth_enabled = True
        
        if local_auth_enabled and not external_auth_enabled:
            self.add_finding(
                'medium',
                'Only Local Authentication Enabled',
                'The Rancher instance relies solely on local authentication without external identity provider integration.',
                'Enable external authentication (LDAP, SAML, OAuth) for centralized user management and enhanced security.'
            )
    
    # Check for MFA enforcement
    settings = self.api_request('settings')
    mfa_enabled = False
    
    if settings.get('data'):
        for setting in settings['data']:
            if 'mfa' in setting.get('id', '').lower():
                mfa_enabled = True
                break
    
    if not mfa_enabled:
        self.add_finding(
            'high',
            'Multi-Factor Authentication Not Enforced',
            'MFA is not configured or enforced for Rancher access.',
            'Enable and enforce MFA for all user accounts, especially administrators.'
        )

def check_api_tokens(self):
    """Audit API tokens and their configurations"""
    print("[*] Checking API tokens...")
    
    tokens = self.api_request('tokens')
    
    if tokens.get('data'):
        expired_count = 0
        no_expiry_count = 0
        old_tokens = []
        
        for token in tokens['data']:
            # Check for tokens without expiration
            if not token.get('expiresAt'):
                no_expiry_count += 1
            else:
                # Check for expired tokens still active
                expiry = datetime.fromisoformat(token['expiresAt'].replace('Z', '+00:00'))
                if expiry < datetime.now(expiry.tzinfo):
                    expired_count += 1
                
                # Check for old tokens (>90 days)
                created = datetime.fromisoformat(token.get('created', '').replace('Z', '+00:00'))
                if datetime.now(created.tzinfo) - created > timedelta(days=90):
                    old_tokens.append(token.get('name', 'Unknown'))
        
        if no_expiry_count > 0:
            self.add_finding(
                'critical',
                f'{no_expiry_count} API Tokens Without Expiration',
                f'Found {no_expiry_count} API tokens that never expire, creating long-term security risks.',
                'Set expiration dates for all API tokens. Implement token rotation policy (recommended: 90 days).'
            )
        
        if expired_count > 0:
            self.add_finding(
                'low',
                f'{expired_count} Expired Tokens Not Cleaned Up',
                'Expired tokens are still present in the system.',
                'Implement automated cleanup of expired tokens.'
            )
        
        if old_tokens:
            self.add_finding(
                'medium',
                f'{len(old_tokens)} Long-Lived Active Tokens',
                f'Found tokens active for more than 90 days: {", ".join(old_tokens[:5])}',
                'Rotate API tokens regularly. Consider implementing automatic token rotation.'
            )

def check_rbac_configuration(self):
    """Audit RBAC roles and bindings"""
    print("[*] Checking RBAC configuration...")
    
    # Check cluster role template bindings
    bindings = self.api_request('clusterroletemplatebindings')
    
    if bindings.get('data'):
        admin_bindings = []
        
        for binding in bindings['data']:
            role = binding.get('roleTemplateId', '')
            user = binding.get('userId', binding.get('groupPrincipalId', 'Unknown'))
            
            # Check for cluster-admin or owner roles
            if 'admin' in role.lower() or 'owner' in role.lower():
                admin_bindings.append(f"{user} -> {role}")
        
        if len(admin_bindings) > 5:
            self.add_finding(
                'high',
                f'Excessive Cluster Admin Privileges',
                f'Found {len(admin_bindings)} cluster-admin or owner role bindings. This violates principle of least privilege.',
                'Review and reduce admin privileges. Implement more granular RBAC roles.'
            )
    
    # Check for overly permissive global roles
    global_roles = self.api_request('globalroles')
    
    if global_roles.get('data'):
        for role in global_roles['data']:
            rules = role.get('rules', [])
            for rule in rules:
                resources = rule.get('resources', [])
                verbs = rule.get('verbs', [])
                
                # Check for wildcard permissions
                if '*' in resources or '*' in verbs:
                    self.add_finding(
                        'high',
                        f'Wildcard Permissions in Role: {role.get("name", "Unknown")}',
                        'Role contains wildcard (*) permissions which grant excessive access.',
                        'Replace wildcard permissions with specific resource and verb permissions.'
                    )

def check_secrets_security(self):
    """Audit secrets management and encryption"""
    print("[*] Checking secrets security...")
    
    # Check clusters for secrets encryption configuration
    clusters = self.api_request('clusters')
    
    if clusters.get('data'):
        for cluster in clusters['data']:
            cluster_name = cluster.get('name', 'Unknown')
            
            # Check for secrets encryption at rest
            encryption_config = cluster.get('rancherKubernetesEngineConfig', {}).get('services', {}).get('kubeApi', {}).get('secretsEncryptionConfig')
            
            if not encryption_config or not encryption_config.get('enabled'):
                self.add_finding(
                    'high',
                    f'Secrets Encryption Not Enabled: {cluster_name}',
                    f'Cluster "{cluster_name}" does not have secrets encryption at rest enabled.',
                    'Enable secrets encryption at rest using encryption providers (KMS, aesgcm, etc.).'
                )
            
            # Check for external secrets manager integration
            # This would require checking for specific operators or configurations
            self.add_finding(
                'info',
                f'Review External Secrets Management: {cluster_name}',
                f'Verify if cluster "{cluster_name}" integrates with external secrets managers (Vault, AWS Secrets Manager, etc.).',
                'Consider implementing external secrets management for enhanced security and rotation capabilities.'
            )

def check_network_policies(self):
    """Check for network policy configurations"""
    print("[*] Checking network policies...")
    
    clusters = self.api_request('clusters')
    
    if clusters.get('data'):
        for cluster in clusters['data']:
            cluster_name = cluster.get('name', 'Unknown')
            
            # Check if network provider supports network policies
            network_config = cluster.get('rancherKubernetesEngineConfig', {}).get('network', {})
            plugin = network_config.get('plugin', '')
            
            if plugin not in ['canal', 'calico', 'cilium']:
                self.add_finding(
                    'medium',
                    f'Network Plugin May Not Support Network Policies: {cluster_name}',
                    f'Cluster "{cluster_name}" uses network plugin "{plugin}" which may have limited network policy support.',
                    'Use a network plugin that fully supports Kubernetes Network Policies (Canal, Calico, Cilium).'
                )

def check_pod_security(self):
    """Audit Pod Security Policies and Pod Security Standards"""
    print("[*] Checking pod security configurations...")
    
    clusters = self.api_request('clusters')
    
    if clusters.get('data'):
        for cluster in clusters['data']:
            cluster_name = cluster.get('name', 'Unknown')
            
            # Check for PSP configuration (deprecated but may still be in use)
            psp_config = cluster.get('defaultPodSecurityPolicyTemplateId')
            
            if not psp_config:
                self.add_finding(
                    'critical',
                    f'No Pod Security Policy Configured: {cluster_name}',
                    f'Cluster "{cluster_name}" has no default pod security policy, allowing unrestricted pod configurations.',
                    'Implement Pod Security Admission (PSA) with appropriate security standards (restricted, baseline, or privileged).'
                )
            
            # Check for privileged containers allowed
            services = cluster.get('rancherKubernetesEngineConfig', {}).get('services', {})
            if services:
                # Check kubelet configuration
                kubelet = services.get('kubelet', {})
                if kubelet.get('extraArgs', {}).get('allow-privileged') == 'true':
                    self.add_finding(
                        'high',
                        f'Privileged Containers Allowed: {cluster_name}',
                        f'Cluster "{cluster_name}" allows privileged containers which can compromise node security.',
                        'Disable privileged containers unless absolutely necessary. Use PSP/PSA to restrict privileges.'
                    )

def check_tls_configuration(self):
    """Audit TLS/SSL configurations"""
    print("[*] Checking TLS/SSL configuration...")
    
    # Check Rancher server certificate
    try:
        response = requests.get(self.rancher_url, verify=True, timeout=10)
        # If we get here without exception, certificate is valid
        self.add_finding(
            'info',
            'Valid TLS Certificate',
            'Rancher server has a valid TLS certificate.',
            'Ensure certificate auto-renewal is configured and monitor expiration dates.'
        )
    except requests.exceptions.SSLError:
        self.add_finding(
            'high',
            'Invalid or Self-Signed TLS Certificate',
            'Rancher server is using an invalid or self-signed TLS certificate.',
            'Use a valid certificate from a trusted CA. Configure cert-manager for automated certificate management.'
        )
    except Exception as e:
        print(f"[WARNING] Could not verify TLS: {e}")
    
    # Check clusters for TLS configuration
    clusters = self.api_request('clusters')
    
    if clusters.get('data'):
        for cluster in clusters['data']:
            cluster_name = cluster.get('name', 'Unknown')
            
            # Check for insecure registries
            private_registries = cluster.get('rancherKubernetesEngineConfig', {}).get('privateRegistries', [])
            
            for registry in private_registries:
                if registry.get('isDefault') and not registry.get('url', '').startswith('https://'):
                    self.add_finding(
                        'medium',
                        f'Insecure Private Registry: {cluster_name}',
                        f'Cluster "{cluster_name}" has a private registry configured without HTTPS.',
                        'Configure all private registries to use HTTPS with valid certificates.'
                    )

def check_audit_logging(self):
    """Check audit logging configuration"""
    print("[*] Checking audit logging...")
    
    clusters = self.api_request('clusters')
    
    if clusters.get('data'):
        for cluster in clusters['data']:
            cluster_name = cluster.get('name', 'Unknown')
            
            # Check for audit log configuration
            services = cluster.get('rancherKubernetesEngineConfig', {}).get('services', {})
            kube_api = services.get('kubeApi', {})
            audit_log = kube_api.get('auditLog')
            
            if not audit_log or not audit_log.get('enabled'):
                self.add_finding(
                    'medium',
                    f'Audit Logging Not Enabled: {cluster_name}',
                    f'Cluster "{cluster_name}" does not have Kubernetes audit logging enabled.',
                    'Enable audit logging for security monitoring, compliance, and incident investigation.'
                )

def check_image_security(self):
    """Check image scanning and registry security"""
    print("[*] Checking image security configurations...")
    
    # Check if image scanning is configured
    settings = self.api_request('settings')
    
    image_scanning_enabled = False
    if settings.get('data'):
        for setting in settings['data']:
            if 'scan' in setting.get('id', '').lower():
                image_scanning_enabled = True
                break
    
    if not image_scanning_enabled:
        self.add_finding(
            'high',
            'Image Scanning Not Configured',
            'No image vulnerability scanning appears to be configured in Rancher.',
            'Integrate image scanning tools (Trivy, Anchore, etc.) and enforce scanning policies before deployment.'
        )

def check_backup_configuration(self):
    """Check backup and disaster recovery configurations"""
    print("[*] Checking backup configuration...")
    
    # This is a placeholder - actual implementation would check etcd backups
    self.add_finding(
        'info',
        'Verify Backup Configuration',
        'Ensure regular backups of etcd and Rancher state are configured.',
        'Configure automated backups with retention policies. Test restore procedures regularly.'
    )

def run_full_audit(self):
    """Run all security checks"""
    print("\n" + "="*60)
    print("RANCHER SECURITY AUDIT")
    print("="*60)
    print(f"Target: {self.rancher_url}")
    print(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*60 + "\n")
    
    # Run all checks
    self.check_authentication_config()
    self.check_api_tokens()
    self.check_rbac_configuration()
    self.check_secrets_security()
    self.check_network_policies()
    self.check_pod_security()
    self.check_tls_configuration()
    self.check_audit_logging()
    self.check_image_security()
    self.check_backup_configuration()
    
    print("\n" + "="*60)
    print("AUDIT COMPLETE")
    print("="*60)

def generate_report(self, output_format='text'):
    """Generate security audit report"""
    if output_format == 'text':
        return self._generate_text_report()
    elif output_format == 'json':
        return json.dumps(self.findings, indent=2)
    elif output_format == 'html':
        return self._generate_html_report()

def _generate_text_report(self):
    """Generate text format report"""
    report = []
    report.append("\n" + "="*60)
    report.append("RANCHER SECURITY AUDIT REPORT")
    report.append("="*60)
    report.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    report.append(f"Rancher URL: {self.rancher_url}")
    report.append("")
    
    # Summary
    report.append("FINDINGS SUMMARY:")
    report.append(f"  CRITICAL: {len(self.findings['critical'])}")
    report.append(f"  HIGH:     {len(self.findings['high'])}")
    report.append(f"  MEDIUM:   {len(self.findings['medium'])}")
    report.append(f"  LOW:      {len(self.findings['low'])}")
    report.append(f"  INFO:     {len(self.findings['info'])}")
    report.append("")
    
    # Detailed findings
    for severity in ['critical', 'high', 'medium', 'low', 'info']:
        if self.findings[severity]:
            report.append("="*60)
            report.append(f"{severity.upper()} FINDINGS")
            report.append("="*60)
            
            for i, finding in enumerate(self.findings[severity], 1):
                report.append(f"\n[{severity.upper()}-{i}] {finding['title']}")
                report.append(f"Description: {finding['description']}")
                report.append(f"Recommendation: {finding['recommendation']}")
                report.append("")
    
    report.append("="*60)
    report.append("END OF REPORT")
    report.append("="*60)
    
    return "\n".join(report)

def _generate_html_report(self):
    """Generate HTML format report"""
    severity_colors = {
        'critical': '#dc3545',
        'high': '#fd7e14',
        'medium': '#ffc107',
        'low': '#17a2b8',
        'info': '#6c757d'
    }
    
    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Rancher Security Audit Report</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }}
            .container {{ max-width: 1200px; margin: 0 auto; background-color: white; padding: 30px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }}
            h1 {{ color: #333; border-bottom: 3px solid #007bff; padding-bottom: 10px; }}
            .summary {{ background-color: #f8f9fa; padding: 20px; border-radius: 5px; margin: 20px 0; }}
            .finding {{ margin: 20px 0; padding: 15px; border-left: 4px solid; border-radius: 3px; }}
            .finding h3 {{ margin-top: 0; }}
            .timestamp {{ color: #6c757d; font-size: 0.9em; }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Rancher Security Audit Report</h1>
            <p class="timestamp">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p><strong>Rancher URL:</strong> {self.rancher_url}</p>
            
            <div class="summary">
                <h2>Findings Summary</h2>
                <p><strong>CRITICAL:</strong> {len(self.findings['critical'])}</p>
                <p><strong>HIGH:</strong> {len(self.findings['high'])}</p>
                <p><strong>MEDIUM:</strong> {len(self.findings['medium'])}</p>
                <p><strong>LOW:</strong> {len(self.findings['low'])}</p>
                <p><strong>INFO:</strong> {len(self.findings['info'])}</p>
            </div>
    """
    
    for severity in ['critical', 'high', 'medium', 'low', 'info']:
        if self.findings[severity]:
            html += f"<h2>{severity.upper()} Findings</h2>"
            for finding in self.findings[severity]:
                html += f"""
                <div class="finding" style="border-color: {severity_colors[severity]}; background-color: {severity_colors[severity]}10;">
                    <h3>{finding['title']}</h3>
                    <p><strong>Description:</strong> {finding['description']}</p>
                    <p><strong>Recommendation:</strong> {finding['recommendation']}</p>
                </div>
                """
    
    html += """
        </div>
    </body>
    </html>
    """
    
    return html
```

def main():
parser = argparse.ArgumentParser(description=‘Rancher Security Audit Tool’)
parser.add_argument(’–config’, required=True, help=‘Path to configuration file’)
parser.add_argument(’–full-scan’, action=‘store_true’, help=‘Run full security audit’)
parser.add_argument(’–check’, help=‘Run specific check (authentication, secrets, rbac, etc.)’)
parser.add_argument(’–output’, help=‘Output file for report’)
parser.add_argument(’–format’, choices=[‘text’, ‘json’, ‘html’], default=‘text’, help=‘Report format’)

```
args = parser.parse_args()

# Load configuration
try:
    with open(args.config, 'r') as f:
        config = yaml.safe_load(f)
except Exception as e:
    print(f"[ERROR] Failed to load configuration: {e}")
    sys.exit(1)

# Initialize auditor
auditor = RancherSecurityAuditor(
    rancher_url=config['rancher']['url'],
    access_key=config['rancher']['access_key'],
    secret_key=config['rancher']['secret_key'],
    verify_ssl=config.get('verify_ssl', True)
)

# Run audit
if args.full_scan:
    auditor.run_full_audit()
elif args.check:
    check_method = f"check_{args.check}"
    if hasattr(auditor, check_method):
        getattr(auditor, check_method)()
    else:
        print(f"[ERROR] Unknown check: {args.check}")
        sys.exit(1)
else:
    print("[ERROR] Please specify --full-scan or --check")
    sys.exit(1)

# Generate report
report = auditor.generate_report(args.format)

if args.output:
    with open(args.output, 'w') as f:
        f.write(report)
    print(f"\n[+] Report saved to: {args.output}")
else:
    print(report)
```

if **name** == “**main**”:
main()
