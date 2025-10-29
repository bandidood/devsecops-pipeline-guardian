# DevSecOps Pipeline Guardian 🛡️

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.11+-blue.svg)
![Docker](https://img.shields.io/badge/docker-ready-brightgreen.svg)

A comprehensive security automation platform that implements **Shift-Left Security** principles by integrating security scanning directly into CI/CD pipelines.

## 🎯 Overview

DevSecOps Pipeline Guardian is an enterprise-grade security platform that orchestrates multiple security scanning tools to provide comprehensive vulnerability detection across your entire development lifecycle:

- **SAST** (Static Application Security Testing) with SonarQube & Semgrep
- **DAST** (Dynamic Application Security Testing) with OWASP ZAP
- **Dependency Scanning** with OWASP Dependency-Check & Snyk
- **Container Security** with Trivy & Clair
- **Policy as Code** with Open Policy Agent (OPA)

## ✨ Features

### Core Capabilities
- 🔍 **Multi-Tool Security Scanning**: Orchestrates multiple industry-standard security tools
- 🚀 **CI/CD Integration**: Native support for GitHub Actions, GitLab CI, and Jenkins
- 📊 **Centralized Dashboard**: Real-time vulnerability tracking and management
- 🔒 **Policy Enforcement**: Automated security gates with OPA policies
- 📈 **Metrics & Reporting**: Comprehensive security metrics and compliance reports
- 🔄 **Automated Workflows**: Parallel scan execution for optimal performance
- 🎨 **Extensible Architecture**: Plugin-based design for custom integrations

### Security Scanning Types

#### SAST - Static Analysis
- Code quality and security vulnerabilities
- CWE/OWASP Top 10 detection
- Custom rule configurations
- Multi-language support

#### DAST - Dynamic Analysis
- Runtime vulnerability detection
- API security testing
- Authentication testing
- Session management analysis

#### Dependency Scanning
- CVE detection in dependencies
- License compliance checking
- Outdated package detection
- Automated fix suggestions

#### Container Security
- Image vulnerability scanning
- Configuration hardening
- Secret detection
- Compliance validation

## 🚀 Quick Start

### Prerequisites

- Docker & Docker Compose
- Python 3.11+
- Git
- 8GB RAM minimum
- 20GB free disk space

### Installation

1. **Clone the repository**
```bash
git clone https://github.com/yourorg/devsecops-pipeline-guardian.git
cd devsecops-pipeline-guardian
```

2. **Set up environment variables**
```bash
cp .env.example .env
# Edit .env with your credentials
```

3. **Start the platform**
```bash
docker-compose up -d
```

4. **Access the dashboard**
```
http://localhost:3000
```

### Services & Ports

| Service | Port | Description |
|---------|------|-------------|
| Main API | 8000 | Core application API |
| Dashboard | 3000 | Web UI |
| SonarQube | 9000 | SAST scanning |
| OWASP ZAP | 8090 | DAST scanning |
| Trivy | 8091 | Container scanning |
| OPA | 8181 | Policy evaluation |
| Prometheus | 9090 | Metrics |
| Grafana | 3001 | Monitoring dashboards |

## 📖 Usage

### Running a Security Scan

#### CLI Usage
```bash
# Full security scan
python -m src.cli scan --type full --target ./my-project

# SAST only
python -m src.cli scan --type sast --target ./my-project

# Container scan
python -m src.cli scan --type container --target myimage:latest

# With policy evaluation
python -m src.cli scan --type full --target ./my-project --evaluate-policy
```

#### API Usage
```python
from src.orchestrator.security_orchestrator import SecurityOrchestrator, ScanType

orchestrator = SecurityOrchestrator(config)
results = await orchestrator.run_scan(
    scan_type=ScanType.FULL,
    target="./my-project",
    options={"include_dast": True, "include_container": True}
)
```

### CI/CD Integration

#### GitHub Actions
```yaml
- name: Run Security Scan
  uses: ./.github/workflows/security-pipeline.yml
  with:
    scan-type: full
    fail-on: high
```

#### GitLab CI
```yaml
include:
  - local: '.gitlab-ci.yml'

security-scan:
  extends: .security-template
  variables:
    SCAN_TYPE: "full"
```

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    CI/CD Pipeline                        │
│  (GitHub Actions / GitLab CI / Jenkins)                 │
└────────────────────┬────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────┐
│            Security Orchestrator                         │
│  ┌──────────┬──────────┬──────────┬──────────┐         │
│  │   SAST   │   DAST   │Dependency│Container │         │
│  │ Scanner  │ Scanner  │ Scanner  │ Scanner  │         │
│  └──────────┴──────────┴──────────┴──────────┘         │
└────────────────────┬────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────┐
│          Policy Evaluation Engine (OPA)                  │
│    ┌────────────────────────────────────┐               │
│    │  Security Gates & Compliance Rules │               │
│    └────────────────────────────────────┘               │
└────────────────────┬────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────┐
│               Results & Reporting                        │
│    ┌──────────────┬────────────┬──────────────┐        │
│    │  Dashboard   │   Reports  │  Integrations│        │
│    └──────────────┴────────────┴──────────────┘        │
└─────────────────────────────────────────────────────────┘
```

## 🔧 Configuration

### Scan Configuration

Create a `security-config.yaml`:

```yaml
sast:
  tools:
    - sonarqube
    - semgrep
  severity_threshold: HIGH
  fail_on_new_issues: true

dast:
  tools:
    - zap
  target_url: http://localhost:8080
  scan_type: baseline  # or full

dependency:
  tools:
    - snyk
    - dependency-check
  cvss_threshold: 7.0

container:
  tools:
    - trivy
  severity: CRITICAL,HIGH
  ignore_unfixed: false

policy:
  enabled: true
  policy_file: config/opa/security-gates.rego
```

### OPA Policies

Customize security policies in `config/opa/security-gates.rego`:

```rego
# Allow deployment only if no critical vulnerabilities
allow {
    not has_critical_vulnerabilities
    code_coverage_sufficient
    no_hardcoded_secrets
}
```

## 📊 Reports & Metrics

### Generated Reports

- **HTML Reports**: Human-readable vulnerability reports
- **JSON/SARIF**: Machine-readable for tool integration
- **PDF Reports**: Executive summaries
- **Trend Analysis**: Historical vulnerability tracking

### Metrics Collected

- Vulnerability count by severity
- Mean time to remediation (MTTR)
- Security score trends
- Policy compliance rate
- Scan execution times

## 🧪 Testing

```bash
# Run unit tests
pytest tests/unit

# Run integration tests
pytest tests/integration

# Run with coverage
pytest --cov=src --cov-report=html
```

## 🤝 Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Development Setup

```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install development dependencies
pip install -r requirements-dev.txt

# Install pre-commit hooks
pre-commit install

# Run linters
flake8 src/
black src/
mypy src/
```

## 📚 Documentation

- [Architecture Overview](docs/architecture/README.md)
- [API Documentation](docs/api/README.md)
- [User Guide](docs/guides/user-guide.md)
- [Security Policy](SECURITY.md)

## 🔐 Security

See [SECURITY.md](SECURITY.md) for our security policy and how to report vulnerabilities.

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [OWASP](https://owasp.org/) for security tools and guidelines
- [Trivy](https://github.com/aquasecurity/trivy) for container scanning
- [Semgrep](https://semgrep.dev/) for SAST capabilities
- [Open Policy Agent](https://www.openpolicyagent.org/) for policy enforcement

## 📞 Support

- 📧 Email: security@example.com
- 💬 Slack: [Join our community](https://slack.example.com)
- 🐛 Issues: [GitHub Issues](https://github.com/yourorg/devsecops-pipeline-guardian/issues)
- 📖 Docs: [Documentation](https://docs.example.com)

---

Made with ❤️ by the DevSecOps Team
