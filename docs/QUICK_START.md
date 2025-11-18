# Quick Start Guide - DevSecOps Pipeline Guardian

## Prerequisites

- Docker & Docker Compose
- Python 3.11+
- Git
- Minimum 8GB RAM
- 20GB free disk space

## Installation

### 1. Clone the Repository

```bash
git clone https://github.com/yourorg/devsecops-pipeline-guardian.git
cd devsecops-pipeline-guardian
```

### 2. Configure Environment

```bash
# Copy environment template
cp .env.example .env

# Edit configuration
nano .env
```

**Required Environment Variables:**

```env
# SonarQube
SONAR_HOST_URL=http://sonarqube:9000
SONAR_TOKEN=your-sonar-token

# Snyk
SNYK_TOKEN=your-snyk-token

# NVD API (for dependency scanning)
NVD_API_KEY=your-nvd-api-key

# OPA
OPA_URL=http://opa:8181

# Notifications (optional)
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your-email@example.com
SMTP_PASSWORD=your-password
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/YOUR/WEBHOOK/URL
TEAMS_WEBHOOK_URL=https://outlook.office.com/webhook/YOUR/WEBHOOK/URL
```

### 3. Start Services

```bash
# Start all services
docker-compose up -d

# Check service status
docker-compose ps

# View logs
docker-compose logs -f devsecops-guardian
```

**Services Started:**
- DevSecOps Guardian API (port 8000)
- SonarQube (port 9000)
- OWASP ZAP (port 8090)
- Trivy (port 8091)
- OPA (port 8181)
- Prometheus (port 9090)
- Grafana (port 3001)
- PostgreSQL (port 5432)
- Redis (port 6379)

## First Scan

### Using CLI

```bash
# Full security scan
python -m src.cli scan \
  --type full \
  --target ./my-project \
  --evaluate-policy

# SAST only
python -m src.cli scan \
  --type sast \
  --target ./my-project

# Container scan
python -m src.cli scan \
  --type container \
  --target nginx:latest

# Export results as HTML
python -m src.cli scan \
  --type full \
  --target ./my-project \
  --output report.html \
  --format html
```

### Using API

```bash
# Start a scan
curl -X POST http://localhost:8000/api/v1/scans \
  -H "Content-Type: application/json" \
  -d '{
    "scan_type": "full",
    "target": "/path/to/project",
    "options": {
      "include_dast": true,
      "include_container": true,
      "evaluate_policy": true
    }
  }'

# Response:
# {
#   "scan_id": "550e8400-e29b-41d4-a716-446655440000",
#   "status": "pending",
#   "message": "full scan initiated"
# }

# Check scan status
curl http://localhost:8000/api/v1/scans/{scan_id}/status

# Get results
curl http://localhost:8000/api/v1/scans/{scan_id}

# Export as SARIF
curl "http://localhost:8000/api/v1/scans/{scan_id}/export?format=sarif" \
  -o results.sarif
```

### Using Python SDK

```python
import asyncio
from src.orchestrator.security_orchestrator import SecurityOrchestrator, ScanType
import yaml

# Load configuration
with open('security-config.yaml', 'r') as f:
    config = yaml.safe_load(f)

# Create orchestrator
orchestrator = SecurityOrchestrator(config)

# Run scan
async def run_scan():
    results = await orchestrator.run_scan(
        scan_type=ScanType.FULL,
        target='./my-project',
        options={
            'include_dast': True,
            'include_container': True,
            'evaluate_policy': True
        }
    )

    print(f"Scan ID: {results['scan_id']}")
    print(f"Security Score: {results['policy_evaluation']['security_score']}/100")
    print(f"Decision: {results['policy_evaluation']['decision']}")

    # Export results
    html_report = orchestrator.export_results(
        results['scan_id'],
        format='html'
    )

    with open('scan-report.html', 'w') as f:
        f.write(html_report)

# Run
asyncio.run(run_scan())
```

## Access Web Interfaces

### API Documentation
- Swagger UI: http://localhost:8000/api/docs
- ReDoc: http://localhost:8000/api/redoc

### Monitoring & Visualization
- Grafana: http://localhost:3001 (admin/admin)
- Prometheus: http://localhost:9090
- SonarQube: http://localhost:9000 (admin/admin)

### Security Tools
- OWASP ZAP: http://localhost:8090
- Trivy: http://localhost:8091

## Configure Security Policies

Edit `config/opa/devsecops-policies.rego`:

```rego
# Customize thresholds
thresholds := {
    "critical_vulnerabilities": 0,
    "high_vulnerabilities": 5,
    "medium_vulnerabilities": 20,
    "security_score_min": 70
}
```

Test policies:

```bash
# Validate policy
opa test config/opa/

# Evaluate policy manually
opa eval -i scan-results.json \
  -d config/opa/devsecops-policies.rego \
  "data.devsecops.security.allow"
```

## Configure Notifications

Edit `security-config.yaml` or use example:

```bash
cp examples/notification-config.yaml security-config.yaml
```

Update with your credentials:

```yaml
notifications:
  enabled: true
  channels:
    - email
    - slack
  email:
    smtp_host: smtp.gmail.com
    smtp_user: your-email@example.com
    smtp_password: ${EMAIL_PASSWORD}
    recipients:
      - security-team@example.com
  slack:
    webhook_url: ${SLACK_WEBHOOK_URL}
    channel: '#security-alerts'
```

## CI/CD Integration

### GitHub Actions

Add to your workflow:

```yaml
- name: Run Security Scan
  uses: ./.github/workflows/security-scan.yml
  with:
    scan-type: full
    fail-on: high
```

### GitLab CI

```yaml
include:
  - local: '.gitlab-ci.yml'

security-scan:
  extends: .security-template
  variables:
    SCAN_TYPE: "full"
```

### Jenkins

```groovy
pipeline {
    agent any
    stages {
        stage('Security Scan') {
            steps {
                sh 'python -m src.cli scan --type full --target .'
            }
        }
    }
}
```

## Monitoring with Grafana

1. Access Grafana: http://localhost:3001
2. Login with admin/admin
3. Import dashboard from `config/monitoring/grafana-dashboard-security.json`
4. View real-time security metrics

## Troubleshooting

### Services not starting

```bash
# Check Docker logs
docker-compose logs

# Restart services
docker-compose restart

# Rebuild if needed
docker-compose up -d --build
```

### Scan failures

```bash
# Check API logs
docker-compose logs devsecops-guardian

# Verify scanner tools
docker-compose exec devsecops-guardian semgrep --version
docker-compose exec devsecops-guardian trivy --version
```

### Policy evaluation errors

```bash
# Test OPA is running
curl http://localhost:8181/health

# Validate policy file
opa check config/opa/devsecops-policies.rego
```

## Next Steps

1. **Customize Policies**: Edit OPA policies for your security requirements
2. **Configure Notifications**: Set up email/Slack/Teams alerts
3. **Integrate with CI/CD**: Add to your pipeline
4. **Review Dashboards**: Monitor security trends in Grafana
5. **Schedule Scans**: Set up periodic scans with cron

## Support

- Documentation: [docs/](../docs/)
- API Reference: [docs/API.md](API.md)
- Issues: https://github.com/yourorg/devsecops-pipeline-guardian/issues
- Email: security@example.com
