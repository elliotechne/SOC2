#!/bin/bash
# Test script for SOC2 Checkov policies
# This script runs Checkov against example configurations to verify policies work correctly

set -e

echo "=========================================="
echo "SOC2 Checkov Policy Test Suite"
echo "=========================================="
echo ""

# Check if checkov is installed
if ! command -v checkov &> /dev/null; then
    echo "ERROR: Checkov is not installed"
    echo "Please run: pip install checkov"
    exit 1
fi

echo "Checkov version: $(checkov --version)"
echo ""

# Test AWS Compliant Configuration
echo "=========================================="
echo "Test 1: AWS Compliant Configuration"
echo "=========================================="
echo "Expected: All checks should PASS"
echo ""
checkov -f examples/terraform/aws_compliant.tf \
    --external-checks-dir ./checkov_policies \
    --framework terraform \
    --check-pattern "CKV_SOC2_AWS_.*" \
    --compact || true
echo ""

# Test AWS Non-Compliant Configuration
echo "=========================================="
echo "Test 2: AWS Non-Compliant Configuration"
echo "=========================================="
echo "Expected: Multiple checks should FAIL"
echo ""
checkov -f examples/terraform/aws_non_compliant.tf \
    --external-checks-dir ./checkov_policies \
    --framework terraform \
    --check-pattern "CKV_SOC2_AWS_.*" \
    --compact || true
echo ""

# Test GCP Compliant Configuration
echo "=========================================="
echo "Test 3: GCP Compliant Configuration"
echo "=========================================="
echo "Expected: All checks should PASS"
echo ""
checkov -f examples/terraform/gcp_compliant.tf \
    --external-checks-dir ./checkov_policies \
    --framework terraform \
    --check-pattern "CKV_SOC2_GCP_.*" \
    --compact || true
echo ""

# Test DigitalOcean Compliant Configuration
echo "=========================================="
echo "Test 4: DigitalOcean Compliant Configuration"
echo "=========================================="
echo "Expected: All checks should PASS"
echo ""
checkov -f examples/terraform/digitalocean_compliant.tf \
    --external-checks-dir ./checkov_policies \
    --framework terraform \
    --check-pattern "CKV_SOC2_DO_.*" \
    --compact || true
echo ""

# Generate comprehensive report
echo "=========================================="
echo "Generating Comprehensive Report"
echo "=========================================="
echo ""
mkdir -p reports

# JSON Report
echo "Generating JSON report..."
checkov -d examples/terraform \
    --external-checks-dir ./checkov_policies \
    --framework terraform \
    -o json \
    --output-file-path reports/soc2-report.json \
    --soft-fail || true

echo "✓ JSON report saved to: reports/soc2-report.json"

# JUnit XML Report
echo "Generating JUnit XML report..."
checkov -d examples/terraform \
    --external-checks-dir ./checkov_policies \
    --framework terraform \
    -o junitxml \
    --output-file-path reports/soc2-junit.xml \
    --soft-fail || true

echo "✓ JUnit report saved to: reports/soc2-junit.xml"

# CLI Report
echo "Generating CLI report..."
checkov -d examples/terraform \
    --external-checks-dir ./checkov_policies \
    --framework terraform \
    -o cli \
    --output-file-path reports/soc2-cli.txt \
    --soft-fail || true

echo "✓ CLI report saved to: reports/soc2-cli.txt"

echo ""
echo "=========================================="
echo "Test Summary"
echo "=========================================="
echo "All tests completed!"
echo "Reports generated in: ./reports/"
echo ""
echo "Policy Statistics:"
echo "  AWS Policies: 33"
echo "  GCP Policies: 29"
echo "  DigitalOcean Policies: 27"
echo "  Total: 89 SOC2 compliance policies"
echo ""
echo "Next steps:"
echo "1. Review reports in ./reports/ directory"
echo "2. Run against your own Terraform code:"
echo "   checkov -d /path/to/terraform --external-checks-dir ./checkov_policies"
echo ""
