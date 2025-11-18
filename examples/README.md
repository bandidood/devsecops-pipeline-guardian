# Configuration Examples

This directory contains example configuration files for DevSecOps Pipeline Guardian.

## Files

### notification-config.yaml
Example notification configuration with email, Slack, and Teams integration.

**Use case:** Setting up security alerts for your team

```bash
cp notification-config.yaml ../security-config.yaml
# Edit with your credentials
```

### full-config.yaml
Complete configuration example with all features enabled.

**Use case:** Production deployment with all scanners and integrations

```bash
cp full-config.yaml ../security-config.yaml
# Customize for your environment
```

## Configuration Sections

### SAST Configuration
```yaml
sast:
  tools:
    - sonarqube
    - semgrep
  severity_threshold: HIGH
  sonar_host_url: http://localhost:9000
  sonar_token: ${SONAR_TOKEN}
```

### DAST Configuration
```yaml
dast:
  tools:
    - zap
  scan_type: baseline
  target_url: http://localhost:8080
  zap_host: http://localhost:8090
```

### Dependency Scanning
```yaml
dependency:
  tools:
    - snyk
    - dependency-check
  cvss_threshold: 7.0
  snyk_token: ${SNYK_TOKEN}
```

### Container Scanning
```yaml
container:
  tools:
    - trivy
  severity: CRITICAL,HIGH
  ignore_unfixed: false
```

### Policy Enforcement
```yaml
policy:
  enabled: true
  opa_url: http://localhost:8181
  policy_package: devsecops.security
  security_score_threshold: 70
```

### Notifications
```yaml
notifications:
  enabled: true
  channels:
    - email
    - slack
  on_failure: true
  on_success: false
```

## Environment Variables

Use environment variables for sensitive data:

```bash
export SONAR_TOKEN="your-token"
export SNYK_TOKEN="your-token"
export SLACK_WEBHOOK_URL="https://hooks.slack.com/..."
export SMTP_PASSWORD="your-password"
```

Or use `.env` file:

```bash
cp ../.env.example ../.env
# Edit .env with your values
```

## Minimal Configuration

For quick testing with minimal setup:

```yaml
sast:
  tools:
    - semgrep

dependency:
  tools:
    - safety

policy:
  enabled: false

notifications:
  enabled: false
```

## Production Configuration

For production deployment:

```yaml
# All scanners enabled
sast:
  tools: [sonarqube, semgrep]
dast:
  tools: [zap]
dependency:
  tools: [snyk, dependency-check]
container:
  tools: [trivy]

# Strict policies
policy:
  enabled: true
  fail_on_violations: true
  security_score_threshold: 80

# Critical thresholds
thresholds:
  critical_vulnerabilities: 0
  high_vulnerabilities: 0
  security_score_min: 80

# Notifications enabled
notifications:
  enabled: true
  channels: [email, slack, teams]
  on_failure: true
  on_warning: true

# Monitoring
monitoring:
  prometheus:
    enabled: true
  grafana:
    enabled: true
```

## Custom Policy Files

Place custom OPA policies in `config/opa/`:

```bash
# Create custom policy
cat > ../config/opa/custom-rules.rego <<EOF
package devsecops.custom

deny["No GPL licenses allowed"] {
    input.dependencies[_].license == "GPL-3.0"
}
EOF
```

## Testing Configuration

Validate configuration before running scans:

```bash
# Test YAML syntax
python -c "import yaml; yaml.safe_load(open('full-config.yaml'))"

# Test policy files
opa test ../config/opa/

# Dry run scan
python -m src.cli scan --type sast --target . --dry-run
```

## Support

For more information:
- [Quick Start Guide](../docs/QUICK_START.md)
- [API Documentation](../docs/API.md)
- [Security Policy](../SECURITY.md)
