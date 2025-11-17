package devsecops.security

import future.keywords.if
import future.keywords.in

# ============================================================================
# DevSecOps Security Policies
# Evaluates scan results and determines deployment decisions
# ============================================================================

# Default deny - fail closed for security
default allow = false

# -----------------
# Main Allow Rule
# -----------------
# Allow deployment if all security gates pass
allow if {
    not has_blocking_vulnerabilities
    security_score_acceptable
    not exceeds_vulnerability_thresholds
}

# -----------------
# Vulnerability Checks
# -----------------

# Block deployment if critical or high vulnerabilities exceed thresholds
has_blocking_vulnerabilities if {
    input.vulnerabilities.critical > thresholds.critical_vulnerabilities
}

has_blocking_vulnerabilities if {
    input.vulnerabilities.high > thresholds.high_vulnerabilities
}

# Check if medium vulnerabilities are within acceptable range
exceeds_vulnerability_thresholds if {
    input.vulnerabilities.medium > thresholds.medium_vulnerabilities
}

# -----------------
# Security Score
# -----------------

# Calculate security score based on vulnerability counts
security_score := score if {
    base_score := 100

    critical_penalty := input.vulnerabilities.critical * 25
    high_penalty := input.vulnerabilities.high * 10
    medium_penalty := input.vulnerabilities.medium * 5
    low_penalty := input.vulnerabilities.low * 1

    total_deductions := critical_penalty + high_penalty + medium_penalty + low_penalty

    score := max([0, base_score - total_deductions])
}

# Security score must meet minimum threshold
security_score_acceptable if {
    security_score >= thresholds.security_score_min
}

# -----------------
# Thresholds Configuration
# -----------------

thresholds := {
    "critical_vulnerabilities": 0,
    "high_vulnerabilities": 5,
    "medium_vulnerabilities": 20,
    "security_score_min": 70
}

# -----------------
# Violations Reporting
# -----------------

# Generate list of policy violations
violations[violation] if {
    input.vulnerabilities.critical > 0
    violation := {
        "type": "CRITICAL_VULNERABILITIES",
        "severity": "CRITICAL",
        "message": sprintf("Found %d critical vulnerabilities - deployment blocked", [input.vulnerabilities.critical]),
        "count": input.vulnerabilities.critical,
        "action": "BLOCK_DEPLOYMENT"
    }
}

violations[violation] if {
    input.vulnerabilities.high > thresholds.high_vulnerabilities
    violation := {
        "type": "HIGH_VULNERABILITY_THRESHOLD_EXCEEDED",
        "severity": "HIGH",
        "message": sprintf("High vulnerabilities (%d) exceed threshold (%d)", [
            input.vulnerabilities.high,
            thresholds.high_vulnerabilities
        ]),
        "count": input.vulnerabilities.high,
        "threshold": thresholds.high_vulnerabilities,
        "action": "REQUIRE_REVIEW"
    }
}

violations[violation] if {
    input.vulnerabilities.medium > thresholds.medium_vulnerabilities
    violation := {
        "type": "MEDIUM_VULNERABILITY_THRESHOLD_EXCEEDED",
        "severity": "MEDIUM",
        "message": sprintf("Medium vulnerabilities (%d) exceed threshold (%d)", [
            input.vulnerabilities.medium,
            thresholds.medium_vulnerabilities
        ]),
        "count": input.vulnerabilities.medium,
        "threshold": thresholds.medium_vulnerabilities,
        "action": "WARNING"
    }
}

violations[violation] if {
    security_score < thresholds.security_score_min
    violation := {
        "type": "SECURITY_SCORE_TOO_LOW",
        "severity": "HIGH",
        "message": sprintf("Security score (%d) below minimum threshold (%d)", [
            security_score,
            thresholds.security_score_min
        ]),
        "score": security_score,
        "threshold": thresholds.security_score_min,
        "action": "BLOCK_DEPLOYMENT"
    }
}

# -----------------
# Scan Type Specific Policies
# -----------------

# SAST Policy
sast_findings_acceptable if {
    results := object.get(input.results, "sast", {})
    summary := object.get(results, "summary", {"critical": 0, "high": 0})

    summary.critical == 0
    summary.high <= 3
}

# Dependency Policy
dependency_findings_acceptable if {
    results := object.get(input.results, "dependency", {})
    summary := object.get(results, "summary", {"critical": 0, "high": 0})

    summary.critical == 0
    summary.high <= 5
}

# Container Policy
container_findings_acceptable if {
    results := object.get(input.results, "container", {})
    summary := object.get(results, "summary", {"critical": 0, "high": 0})

    summary.critical == 0
    summary.high <= 2
}

# DAST Policy
dast_findings_acceptable if {
    results := object.get(input.results, "dast", {})
    summary := object.get(results, "summary", {"high": 0, "medium": 0})

    summary.high <= 3
}

# -----------------
# Metadata
# -----------------

# Policy metadata for reporting
policy_metadata := {
    "name": "DevSecOps Security Gates",
    "version": "1.0.0",
    "description": "Security policy for deployment gates based on vulnerability scan results",
    "updated": "2025-01-17"
}
