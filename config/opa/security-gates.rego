package devsecops.security

import future.keywords.if
import future.keywords.in

# Default deny
default allow = false

# Allow deployment if all security checks pass
allow if {
    not has_critical_vulnerabilities
    not has_high_severity_violations
    code_coverage_sufficient
    no_hardcoded_secrets
    container_scan_passed
}

# Check for critical vulnerabilities (CVSS >= 9.0)
has_critical_vulnerabilities if {
    some vuln in input.vulnerabilities
    vuln.severity == "CRITICAL"
    vuln.cvss_score >= 9.0
}

# Check for high severity violations
has_high_severity_violations if {
    some violation in input.sast_findings
    violation.severity == "HIGH"
    not violation.id in exceptions.allowed_violations
}

# Check code coverage threshold
code_coverage_sufficient if {
    input.coverage.percentage >= 80
}

# Check for hardcoded secrets
no_hardcoded_secrets if {
    count(input.secret_findings) == 0
}

# Container security scan must pass
container_scan_passed if {
    input.container_scan.status == "PASSED"
    count([v | v := input.container_scan.vulnerabilities[_]; v.severity == "CRITICAL"]) == 0
}

# Exceptions for specific use cases
exceptions := {
    "allowed_violations": [
        "RULE-001",  # Example: Development-only code
        "RULE-002"   # Example: Third-party library issue
    ]
}

# Calculate security score
security_score := score if {
    total := 100
    deductions := sum([
        count_critical * 25,
        count_high * 10,
        count_medium * 5,
        count_low * 1
    ])
    
    count_critical := count([v | v := input.vulnerabilities[_]; v.severity == "CRITICAL"])
    count_high := count([v | v := input.vulnerabilities[_]; v.severity == "HIGH"])
    count_medium := count([v | v := input.vulnerabilities[_]; v.severity == "MEDIUM"])
    count_low := count([v | v := input.vulnerabilities[_]; v.severity == "LOW"])
    
    score := max([0, total - deductions])
}

# Require security approval for high-risk changes
require_approval if {
    security_score < 70
}

# Policy for SAST findings
sast_policy := {
    "max_critical": 0,
    "max_high": 5,
    "max_medium": 20,
    "max_low": 50
}

# Policy for dependency vulnerabilities
dependency_policy := {
    "max_critical": 0,
    "max_high": 3,
    "allow_outdated_days": 90
}

# Container image policy
container_policy := {
    "require_scan": true,
    "max_critical": 0,
    "max_high": 2,
    "deny_root_user": true,
    "require_signature": true
}

# Validate SAST results against policy
sast_compliant if {
    count([f | f := input.sast_findings[_]; f.severity == "CRITICAL"]) <= sast_policy.max_critical
    count([f | f := input.sast_findings[_]; f.severity == "HIGH"]) <= sast_policy.max_high
}

# Validate dependency scan results
dependencies_compliant if {
    count([d | d := input.dependency_findings[_]; d.severity == "CRITICAL"]) <= dependency_policy.max_critical
    count([d | d := input.dependency_findings[_]; d.severity == "HIGH"]) <= dependency_policy.max_high
}

# Container compliance check
container_compliant if {
    container_policy.require_scan
    input.container_scan.completed
    not input.container_config.runs_as_root
    input.container_config.signed
}

# Generate violation report
violations[violation] {
    has_critical_vulnerabilities
    violation := {
        "type": "CRITICAL_VULNERABILITY",
        "message": "Critical vulnerabilities found",
        "action": "BLOCK_DEPLOYMENT"
    }
}

violations[violation] {
    not sast_compliant
    violation := {
        "type": "SAST_POLICY_VIOLATION",
        "message": "SAST findings exceed policy limits",
        "action": "REQUIRE_REVIEW"
    }
}

violations[violation] {
    not dependencies_compliant
    violation := {
        "type": "DEPENDENCY_POLICY_VIOLATION",
        "message": "Vulnerable dependencies detected",
        "action": "BLOCK_DEPLOYMENT"
    }
}
