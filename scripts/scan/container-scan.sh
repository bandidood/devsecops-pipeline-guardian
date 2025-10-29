#!/bin/bash

# Container Security Scanning Script
# Runs Trivy and Clair scans on container images

set -e

# Configuration
IMAGE_NAME="${1:-devsecops-guardian:latest}"
REPORTS_DIR="./reports/container"
CONFIG_FILE="./config/container/trivy.yaml"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}╔════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║  Container Security Scanning Suite    ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════╝${NC}"
echo ""
echo "Target Image: $IMAGE_NAME"
echo ""

# Create reports directory
mkdir -p "$REPORTS_DIR"

# Function to check if Docker image exists
check_image() {
    if ! docker image inspect "$IMAGE_NAME" > /dev/null 2>&1; then
        echo -e "${RED}Error: Image $IMAGE_NAME not found${NC}"
        echo "Please build the image first: docker build -t $IMAGE_NAME ."
        exit 1
    fi
}

# Function to run Trivy scan
run_trivy_scan() {
    echo -e "${GREEN}[1/4] Running Trivy vulnerability scan...${NC}"
    
    # Update Trivy database
    trivy image --download-db-only
    
    # Run vulnerability scan
    trivy image \
        --config "$CONFIG_FILE" \
        --severity CRITICAL,HIGH,MEDIUM \
        --format json \
        --output "$REPORTS_DIR/trivy-vuln-report.json" \
        "$IMAGE_NAME"
    
    # Generate human-readable report
    trivy image \
        --severity CRITICAL,HIGH \
        --format table \
        "$IMAGE_NAME" | tee "$REPORTS_DIR/trivy-vuln-report.txt"
    
    # Generate SARIF report for CI/CD integration
    trivy image \
        --format sarif \
        --output "$REPORTS_DIR/trivy-vuln-report.sarif" \
        "$IMAGE_NAME"
    
    echo -e "${GREEN}✓ Trivy vulnerability scan completed${NC}"
}

# Function to run Trivy config scan
run_trivy_config_scan() {
    echo -e "${GREEN}[2/4] Running Trivy configuration scan...${NC}"
    
    trivy image \
        --security-checks config \
        --format json \
        --output "$REPORTS_DIR/trivy-config-report.json" \
        "$IMAGE_NAME"
    
    echo -e "${GREEN}✓ Trivy configuration scan completed${NC}"
}

# Function to run Trivy secret scan
run_trivy_secret_scan() {
    echo -e "${GREEN}[3/4] Running Trivy secret detection...${NC}"
    
    trivy image \
        --security-checks secret \
        --format json \
        --output "$REPORTS_DIR/trivy-secret-report.json" \
        "$IMAGE_NAME"
    
    SECRETS_FOUND=$(jq '.Results[].Secrets | length' "$REPORTS_DIR/trivy-secret-report.json" 2>/dev/null || echo "0")
    
    if [ "$SECRETS_FOUND" -gt 0 ]; then
        echo -e "${RED}⚠ Found $SECRETS_FOUND secrets in the image!${NC}"
    else
        echo -e "${GREEN}✓ No secrets detected${NC}"
    fi
}

# Function to analyze scan results
analyze_results() {
    echo -e "${GREEN}[4/4] Analyzing scan results...${NC}"
    
    # Count vulnerabilities by severity
    CRITICAL=$(jq '[.Results[].Vulnerabilities[]? | select(.Severity=="CRITICAL")] | length' "$REPORTS_DIR/trivy-vuln-report.json" 2>/dev/null || echo "0")
    HIGH=$(jq '[.Results[].Vulnerabilities[]? | select(.Severity=="HIGH")] | length' "$REPORTS_DIR/trivy-vuln-report.json" 2>/dev/null || echo "0")
    MEDIUM=$(jq '[.Results[].Vulnerabilities[]? | select(.Severity=="MEDIUM")] | length' "$REPORTS_DIR/trivy-vuln-report.json" 2>/dev/null || echo "0")
    LOW=$(jq '[.Results[].Vulnerabilities[]? | select(.Severity=="LOW")] | length' "$REPORTS_DIR/trivy-vuln-report.json" 2>/dev/null || echo "0")
    
    echo ""
    echo -e "${BLUE}┌─────────────────────────────────────┐${NC}"
    echo -e "${BLUE}│     Vulnerability Summary           │${NC}"
    echo -e "${BLUE}├─────────────────────────────────────┤${NC}"
    printf "${BLUE}│${NC} ${RED}Critical:${NC} %-24s ${BLUE}│${NC}\n" "$CRITICAL"
    printf "${BLUE}│${NC} ${YELLOW}High:${NC}     %-24s ${BLUE}│${NC}\n" "$HIGH"
    printf "${BLUE}│${NC} Medium:   %-24s ${BLUE}│${NC}\n" "$MEDIUM"
    printf "${BLUE}│${NC} Low:      %-24s ${BLUE}│${NC}\n" "$LOW"
    echo -e "${BLUE}└─────────────────────────────────────┘${NC}"
    echo ""
    
    # Generate summary report
    cat > "$REPORTS_DIR/scan-summary.json" <<EOF
{
  "image": "$IMAGE_NAME",
  "scan_date": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "vulnerabilities": {
    "critical": $CRITICAL,
    "high": $HIGH,
    "medium": $MEDIUM,
    "low": $LOW,
    "total": $((CRITICAL + HIGH + MEDIUM + LOW))
  },
  "secrets_found": $SECRETS_FOUND,
  "reports": {
    "vulnerabilities": "$REPORTS_DIR/trivy-vuln-report.json",
    "configuration": "$REPORTS_DIR/trivy-config-report.json",
    "secrets": "$REPORTS_DIR/trivy-secret-report.json"
  }
}
EOF
    
    # Check if scan should fail
    if [ "$CRITICAL" -gt 0 ]; then
        echo -e "${RED}✗ CRITICAL vulnerabilities found! Build should fail.${NC}"
        return 1
    elif [ "$HIGH" -gt 5 ]; then
        echo -e "${YELLOW}⚠ Too many HIGH vulnerabilities found (threshold: 5)${NC}"
        return 1
    elif [ "$SECRETS_FOUND" -gt 0 ]; then
        echo -e "${RED}✗ Secrets detected in image!${NC}"
        return 1
    else
        echo -e "${GREEN}✓ Container security scan passed${NC}"
        return 0
    fi
}

# Main execution
main() {
    check_image
    run_trivy_scan
    run_trivy_config_scan
    run_trivy_secret_scan
    
    if analyze_results; then
        echo ""
        echo -e "${GREEN}═══════════════════════════════════════${NC}"
        echo -e "${GREEN}  Container Security Scan: PASSED ✓   ${NC}"
        echo -e "${GREEN}═══════════════════════════════════════${NC}"
        exit 0
    else
        echo ""
        echo -e "${RED}═══════════════════════════════════════${NC}"
        echo -e "${RED}  Container Security Scan: FAILED ✗   ${NC}"
        echo -e "${RED}═══════════════════════════════════════${NC}"
        exit 1
    fi
}

# Run main function
main
