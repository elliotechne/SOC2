# Quick Start Guide

This guide will help you get started with SOC2 compliance checking for your Terraform code.

## Prerequisites

- Python 3.7 or higher
- Terraform code to scan
- Basic understanding of SOC2 compliance requirements

## Installation

### Step 1: Install Checkov

```bash
pip install -r requirements.txt
```

Or install Checkov directly:

```bash
pip install checkov
```

### Step 2: Verify Installation

```bash
checkov --version
```

## Running Your First Scan

### Scan a Terraform Directory

```bash
checkov -d /path/to/your/terraform --external-checks-dir ./checkov_policies
```

### Scan Example Files

Test the policies with the provided examples:

```bash
# Scan compliant AWS example (should pass all checks)
checkov -f examples/terraform/aws_compliant.tf --external-checks-dir ./checkov_policies

# Scan non-compliant AWS example (should fail multiple checks)
checkov -f examples/terraform/aws_non_compliant.tf --external-checks-dir ./checkov_policies

# Scan GCP example
checkov -f examples/terraform/gcp_compliant.tf --external-checks-dir ./checkov_policies

# Scan DigitalOcean example
checkov -f examples/terraform/digitalocean_compliant.tf --external-checks-dir ./checkov_policies
```

## Understanding Results

### Passed Check Example

```
Check: CKV_SOC2_AWS_001: "Ensure S3 bucket has server-side encryption enabled (SOC2)"
  PASSED for resource: aws_s3_bucket.compliant_bucket
  File: /examples/terraform/aws_compliant.tf:4-6
  Guide: SOC2 requires encryption of data at rest. Enable S3 bucket encryption.
```

### Failed Check Example

```
Check: CKV_SOC2_AWS_001: "Ensure S3 bucket has server-side encryption enabled (SOC2)"
  FAILED for resource: aws_s3_bucket.non_compliant_bucket
  File: /examples/terraform/aws_non_compliant.tf:4-6
  Guide: SOC2 requires encryption of data at rest. Enable S3 bucket encryption.
```

## Common Use Cases

### 1. Scan Specific Provider

**AWS Only:**
```bash
checkov -d ./terraform --external-checks-dir ./checkov_policies --check CKV_SOC2_AWS
```

**GCP Only:**
```bash
checkov -d ./terraform --external-checks-dir ./checkov_policies --check CKV_SOC2_GCP
```

**DigitalOcean Only:**
```bash
checkov -d ./terraform --external-checks-dir ./checkov_policies --check CKV_SOC2_DO
```

### 2. Generate Reports

**JSON Report:**
```bash
checkov -d ./terraform --external-checks-dir ./checkov_policies -o json > soc2-report.json
```

**HTML Report:**
```bash
checkov -d ./terraform --external-checks-dir ./checkov_policies -o cli --output-file-path ./reports
```

**JUnit XML (for CI/CD):**
```bash
checkov -d ./terraform --external-checks-dir ./checkov_policies -o junitxml > soc2-junit.xml
```

### 3. Scan with Soft Fail (Non-Blocking)

Useful for gradual adoption:

```bash
checkov -d ./terraform --external-checks-dir ./checkov_policies --soft-fail
```

### 4. Skip Specific Checks

If you have a valid reason to skip certain checks:

```bash
checkov -d ./terraform --external-checks-dir ./checkov_policies --skip-check CKV_SOC2_AWS_001,CKV_SOC2_AWS_002
```

## Filtering Results

### By Severity (when configured)

```bash
checkov -d ./terraform --external-checks-dir ./checkov_policies --compact --quiet
```

### By Category

Check specific compliance areas:

```bash
# Only encryption checks
checkov -d ./terraform --external-checks-dir ./checkov_policies | grep -A 5 "ENCRYPTION"

# Only IAM/access control checks
checkov -d ./terraform --external-checks-dir ./checkov_policies | grep -A 5 "IAM"
```

## Inline Suppression

Suppress checks directly in your Terraform code when you have a valid exception:

```hcl
resource "aws_s3_bucket" "logs" {
  #checkov:skip=CKV_SOC2_AWS_001:Log bucket uses default encryption
  bucket = "my-logs-bucket"
}
```

## Integration Examples

### GitHub Actions Workflow

Create `.github/workflows/soc2-compliance.yml`:

```yaml
name: SOC2 Compliance Check

on:
  pull_request:
    branches: [ main, develop ]
  push:
    branches: [ main ]

jobs:
  soc2-scan:
    runs-on: ubuntu-latest

    steps:
    - name: Checkout code
      uses: actions/checkout@v3

    - name: Set up Python
      uses: actions/setup-python@v4
      with:
        python-version: '3.9'

    - name: Install Checkov
      run: pip install checkov

    - name: Run SOC2 Compliance Scan
      run: |
        checkov -d ./terraform \
          --external-checks-dir ./checkov_policies \
          --output junitxml \
          --output-file-path reports/ \
          --soft-fail

    - name: Upload Results
      uses: actions/upload-artifact@v3
      if: always()
      with:
        name: soc2-compliance-report
        path: reports/
```

### GitLab CI Pipeline

Add to `.gitlab-ci.yml`:

```yaml
stages:
  - compliance

soc2-compliance:
  stage: compliance
  image: bridgecrew/checkov:latest
  script:
    - checkov -d terraform/ --external-checks-dir checkov_policies -o junitxml > soc2-report.xml
  artifacts:
    reports:
      junit: soc2-report.xml
    paths:
      - soc2-report.xml
  allow_failure: true
```

### Pre-commit Hook

Create `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/bridgecrewio/checkov
    rev: '2.3.0'
    hooks:
      - id: checkov
        args: ['--external-checks-dir', 'checkov_policies']
```

Install:
```bash
pip install pre-commit
pre-commit install
```

## Troubleshooting

### Issue: Policies Not Loading

**Solution:** Ensure `__init__.py` exists in `checkov_policies/` directory and all policy files are in the same directory.

### Issue: All Checks Passing When They Shouldn't

**Solution:** Verify you're using the `--external-checks-dir` flag pointing to the correct directory.

### Issue: Import Errors

**Solution:** Ensure Checkov is properly installed:
```bash
pip install --upgrade checkov
```

### Issue: False Positives

**Solution:** Use inline suppressions with detailed justifications:
```hcl
#checkov:skip=CKV_SOC2_AWS_001:Documented exception approved by security team on 2024-01-15
```

## Next Steps

1. **Review Failed Checks**: Understand which resources are non-compliant
2. **Prioritize Fixes**: Start with critical security issues (encryption, access control)
3. **Document Exceptions**: Use suppressions for valid exceptions with clear justifications
4. **Automate**: Integrate into your CI/CD pipeline
5. **Monitor**: Regularly scan infrastructure code before deployment

## Getting Help

- Review the full [README.md](README.md) for detailed documentation
- Check example configurations in `examples/terraform/`
- Review individual policy files in `checkov_policies/` for specific requirements
- Open an issue in the repository for bugs or feature requests

## Policy Summary by Category

| Category | AWS Policies | GCP Policies | DO Policies |
|----------|--------------|--------------|-------------|
| Encryption | 7 | 6 | 5 |
| Access Control | 6 | 5 | 5 |
| Logging | 7 | 6 | 5 |
| Network Security | 6 | 6 | 6 |
| Backup & Recovery | 7 | 6 | 6 |
| **Total** | **33** | **29** | **27** |

## Quick Reference: Common Fixes

### Fix: S3 Encryption
```hcl
resource "aws_s3_bucket_server_side_encryption_configuration" "example" {
  bucket = aws_s3_bucket.example.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}
```

### Fix: RDS Encryption
```hcl
resource "aws_db_instance" "example" {
  storage_encrypted = true
  kms_key_id       = aws_kms_key.example.arn
}
```

### Fix: Security Group Restrictions
```hcl
resource "aws_security_group" "example" {
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]  # Not 0.0.0.0/0
  }
}
```

## Maintenance

Keep your policies up to date:

```bash
# Update Checkov
pip install --upgrade checkov

# Pull latest policy updates
git pull origin main
```
