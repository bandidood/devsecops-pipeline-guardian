#!/bin/bash

# OWASP ZAP DAST Scanning Script
# This script runs automated DAST scans using ZAP

set -e

# Configuration
TARGET_URL="${TARGET_URL:-http://localhost:8080}"
ZAP_PORT="${ZAP_PORT:-8090}"
REPORTS_DIR="./reports/dast"
CONFIG_FILE="./config/dast/zap-automation.yaml"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}Starting OWASP ZAP DAST Scan${NC}"
echo "Target: $TARGET_URL"
echo "ZAP Port: $ZAP_PORT"

# Create reports directory
mkdir -p "$REPORTS_DIR"

# Check if ZAP is running
if ! curl -s "http://localhost:$ZAP_PORT" > /dev/null 2>&1; then
    echo -e "${YELLOW}Starting ZAP in daemon mode...${NC}"
    docker run -d --name zap \
        -p "$ZAP_PORT:8080" \
        -v "$(pwd):/zap/wrk:rw" \
        owasp/zap2docker-stable zap.sh -daemon -host 0.0.0.0 -port 8080 \
        -config api.disablekey=true
    
    # Wait for ZAP to start
    echo "Waiting for ZAP to initialize..."
    sleep 10
fi

# Run ZAP automation
echo -e "${GREEN}Running ZAP automation scan...${NC}"
docker exec zap zap-automation.py \
    -autorun "/zap/wrk/$CONFIG_FILE" \
    -target "$TARGET_URL"

# Generate additional reports
echo -e "${GREEN}Generating reports...${NC}"
docker exec zap zap-cli --zap-url "http://localhost:8080" report \
    -o "/zap/wrk/$REPORTS_DIR/zap-report.html" -f html

docker exec zap zap-cli --zap-url "http://localhost:8080" report \
    -o "/zap/wrk/$REPORTS_DIR/zap-report.xml" -f xml

# Check for critical vulnerabilities
echo -e "${GREEN}Analyzing scan results...${NC}"
CRITICAL_VULNS=$(docker exec zap zap-cli --zap-url "http://localhost:8080" alerts -l High | wc -l)

if [ "$CRITICAL_VULNS" -gt 0 ]; then
    echo -e "${RED}Found $CRITICAL_VULNS high/critical vulnerabilities!${NC}"
    echo "Review the report at: $REPORTS_DIR/zap-report.html"
    exit 1
else
    echo -e "${GREEN}No critical vulnerabilities found${NC}"
fi

# Cleanup (optional)
if [ "${CLEANUP:-false}" = "true" ]; then
    echo "Stopping ZAP container..."
    docker stop zap
    docker rm zap
fi

echo -e "${GREEN}DAST scan completed successfully${NC}"
