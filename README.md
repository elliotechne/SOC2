# SOC2 Compliance Checkov Policies for Terraform

Custom Checkov policies for SOC2 compliance validation across AWS, GCP, and DigitalOcean infrastructure as code.

## Overview

This repository contains comprehensive Checkov custom policies designed to validate Terraform configurations against SOC2 compliance requirements. The policies cover the five Trust Services Criteria:

- **Security**: Encryption, access controls, network security
- **Availability**: High availability, backup and recovery
- **Processing Integrity**: Monitoring, logging, audit trails
- **Confidentiality**: Data protection, encryption
- **Privacy**: Access controls, data isolation

## Supported Cloud Providers

- **AWS** (Amazon Web Services)
- **GCP** (Google Cloud Platform)
- **DigitalOcean**

## Policy Categories

### 1. Encryption Policies
- Data at rest encryption (S3, EBS, RDS, GCS, Cloud SQL, etc.)
- Data in transit encryption (HTTPS/TLS for load balancers)
- Customer-managed encryption keys (CMEK)

### 2. Access Control & IAM Policies
- Password policies and MFA requirements
- Least privilege access
- Service account security
- SSH key enforcement
- Public access restrictions

### 3. Logging & Monitoring Policies
- Audit logging (CloudTrail, Cloud Logging)
- Access logs for storage and load balancers
- VPC flow logs
- Log retention policies
- Database audit logs

### 4. Network Security Policies
- Security group and firewall restrictions
- SSH/RDP access controls
- Public IP restrictions
- Network isolation and segmentation
- VPC configuration

### 5. Backup & Recovery Policies
- Automated backups
- Backup retention policies
- Point-in-time recovery
- High availability configurations
- Snapshot policies

## Installation

### Prerequisites

- Python 3.7+
- Checkov installed (`pip install checkov`)
- Terraform configurations to scan

### Setup

1. Clone or download this repository:
```bash
git clone <repository-url>
cd soc2
```

2. The policies are organized in the `checkov_policies/` directory by provider and category.

## Usage

### Running Checkov with Custom Policies

To scan your Terraform code with these custom SOC2 policies:

```bash
checkov -d /path/to/terraform/code --external-checks-dir ./checkov_policies
```

### Scan Specific Provider

For AWS only:
```bash
checkov -d /path/to/terraform/code --external-checks-dir ./checkov_policies --framework terraform --check-pattern "CKV_SOC2_AWS_.*"
```

For GCP only:
```bash
checkov -d /path/to/terraform/code --external-checks-dir ./checkov_policies --framework terraform --check-pattern "CKV_SOC2_GCP_.*"
```

For DigitalOcean only:
```bash
checkov -d /path/to/terraform/code --external-checks-dir ./checkov_policies --framework terraform --check-pattern "CKV_SOC2_DO_.*"
```

### Output Formats

Generate reports in different formats:

```bash
# JSON output
checkov -d /path/to/terraform --external-checks-dir ./checkov_policies -o json

# JUnit XML (for CI/CD integration)
checkov -d /path/to/terraform --external-checks-dir ./checkov_policies -o junitxml

# SARIF (for GitHub integration)
checkov -d /path/to/terraform --external-checks-dir ./checkov_policies -o sarif
```

### CI/CD Integration

#### GitHub Actions

```yaml
name: SOC2 Compliance Check

on: [push, pull_request]

jobs:
  checkov:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2

      - name: Run Checkov
        uses: bridgecrewio/checkov-action@master
        with:
          directory: terraform/
          external_checks_dir: checkov_policies
          framework: terraform
          output_format: sarif
          soft_fail: false
```

#### GitLab CI

```yaml
soc2-compliance:
  stage: test
  image: bridgecrew/checkov:latest
  script:
    - checkov -d terraform/ --external-checks-dir checkov_policies --framework terraform
```

## Policy Reference

### AWS Policies

| Policy ID | Description | Category |
|-----------|-------------|----------|
| CKV_SOC2_AWS_001 | S3 bucket encryption | Encryption |
| CKV_SOC2_AWS_002 | EBS volume encryption | Encryption |
| CKV_SOC2_AWS_003 | RDS encryption | Encryption |
| CKV_SOC2_AWS_101 | IAM password policy | Access Control |
| CKV_SOC2_AWS_102 | IAM user MFA | Access Control |
| CKV_SOC2_AWS_201 | CloudTrail enabled | Logging |
| CKV_SOC2_AWS_301 | Security group ingress restrictions | Network Security |
| CKV_SOC2_AWS_401 | RDS backup retention | Backup & Recovery |

### GCP Policies

| Policy ID | Description | Category |
|-----------|-------------|----------|
| CKV_SOC2_GCP_001 | GCS bucket CMEK encryption | Encryption |
| CKV_SOC2_GCP_002 | Compute disk CMEK encryption | Encryption |
| CKV_SOC2_GCP_101 | Service account key rotation | Access Control |
| CKV_SOC2_GCP_201 | Project logging enabled | Logging |
| CKV_SOC2_GCP_301 | Firewall ingress restrictions | Network Security |
| CKV_SOC2_GCP_401 | Cloud SQL backups | Backup & Recovery |

### DigitalOcean Policies

| Policy ID | Description | Category |
|-----------|-------------|----------|
| CKV_SOC2_DO_001 | Volume encryption | Encryption |
| CKV_SOC2_DO_003 | Load balancer HTTPS | Encryption |
| CKV_SOC2_DO_101 | Droplet SSH keys | Access Control |
| CKV_SOC2_DO_201 | Kubernetes monitoring | Logging |
| CKV_SOC2_DO_301 | Firewall ingress restrictions | Network Security |
| CKV_SOC2_DO_401 | Droplet backups | Backup & Recovery |

## Examples

See the `examples/terraform/` directory for example Terraform configurations that pass and fail these policies.

## Customization

To customize policies for your organization:

1. Edit the policy files in `checkov_policies/`
2. Adjust thresholds (e.g., backup retention days, password length)
3. Add new policies by creating new classes that inherit from `BaseResourceCheck`

Example custom policy:

```python
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck
from checkov.common.models.enums import CheckResult, CheckCategories

class CustomSOC2Check(BaseResourceCheck):
    def __init__(self):
        name = "Your custom check description"
        id = "CKV_SOC2_CUSTOM_001"
        supported_resources = ['resource_type']
        categories = [CheckCategories.ENCRYPTION]
        guideline = "SOC2 guidance for this check"
        super().__init__(name=name, id=id, categories=categories,
                        supported_resources=supported_resources, guideline=guideline)

    def scan_resource_conf(self, conf, entity_type):
        # Your validation logic here
        if meets_requirements:
            return CheckResult.PASSED
        return CheckResult.FAILED

check_custom = CustomSOC2Check()
```

## Suppressing Checks

To suppress specific checks for valid exceptions:

### Inline Suppression (Terraform)

```hcl
resource "aws_s3_bucket" "public_bucket" {
  #checkov:skip=CKV_SOC2_AWS_001:This bucket is intentionally public for static website hosting
  bucket = "my-public-bucket"
}
```

### Configuration File

Create `.checkov.yml`:

```yaml
skip-check:
  - CKV_SOC2_AWS_001  # Skip S3 encryption check
  - CKV_SOC2_GCP_103  # Skip GCS public access check
```

## Contributing

To add new policies:

1. Create a new policy file or add to existing provider files
2. Follow the naming convention: `{provider}_{category}_policies.py`
3. Use policy IDs in the format: `CKV_SOC2_{PROVIDER}_{CATEGORY_NUMBER}`
4. Include clear descriptions and guidelines
5. Add examples to the examples directory

## SOC2 Mapping

These policies map to SOC2 Trust Services Criteria:

- **CC6.1** - Logical and Physical Access Controls → Access Control Policies
- **CC6.6** - Encryption of Data → Encryption Policies
- **CC6.7** - Transmission of Data → Network Security Policies
- **CC7.2** - Detection of System Failures → Monitoring & Logging Policies
- **A1.2** - Backup and Recovery → Backup Policies

## License

MIT License - See LICENSE file for details

## Support

For issues or questions:
- Open an issue in the repository
- Review the examples directory
- Check Checkov documentation: https://www.checkov.io/

## Roadmap

- [ ] Add support for Azure
- [ ] Include custom severity levels
- [ ] Add automated remediation suggestions
- [ ] Integrate with compliance frameworks (HIPAA, PCI-DSS)
- [ ] Add performance benchmarks
