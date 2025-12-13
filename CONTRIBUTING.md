# Contributing to SOC2 Checkov Policies

Thank you for your interest in contributing to this SOC2 compliance policy project! This guide will help you add new policies or improve existing ones.

## Table of Contents

- [Policy Development Guidelines](#policy-development-guidelines)
- [Adding a New Policy](#adding-a-new-policy)
- [Testing Your Policy](#testing-your-policy)
- [Code Style](#code-style)
- [Submission Process](#submission-process)

## Policy Development Guidelines

### 1. Understand SOC2 Requirements

Before creating a policy, ensure you understand:
- Which SOC2 Trust Services Criteria it addresses (CC6.1, CC6.6, CC6.7, CC7.2, A1.2)
- The specific control requirement
- How it applies to infrastructure as code

### 2. Policy Naming Convention

Follow this strict naming convention:

**Policy ID Format:** `CKV_SOC2_{PROVIDER}_{CATEGORY}{NUMBER}`

- **Provider**: AWS, GCP, DO (DigitalOcean)
- **Category Numbers**:
  - `001-099`: Encryption
  - `101-199`: Access Control & IAM
  - `201-299`: Logging & Monitoring
  - `301-399`: Network Security
  - `401-499`: Backup & Recovery

**Examples:**
- `CKV_SOC2_AWS_001`: AWS Encryption policy #1
- `CKV_SOC2_GCP_205`: GCP Logging policy #5
- `CKV_SOC2_DO_304`: DigitalOcean Network policy #4

### 3. File Organization

Place policies in the appropriate file:
- `{provider}_encryption_policies.py`
- `{provider}_access_policies.py`
- `{provider}_logging_policies.py`
- `{provider}_network_policies.py`
- `{provider}_backup_policies.py`

## Adding a New Policy

### Step 1: Create the Policy Class

```python
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck
from checkov.common.models.enums import CheckResult, CheckCategories

class YourNewPolicySOC2(BaseResourceCheck):
    def __init__(self):
        # Clear, concise description
        name = "Ensure [resource] has [requirement] (SOC2)"

        # Unique policy ID following naming convention
        id = "CKV_SOC2_AWS_XXX"

        # Terraform resource types this policy checks
        supported_resources = ['aws_resource_type']

        # Choose appropriate category
        categories = [CheckCategories.ENCRYPTION]

        # Explain why this is required for SOC2
        guideline = "SOC2 requires [control]. [Action to comply]."

        super().__init__(
            name=name,
            id=id,
            categories=categories,
            supported_resources=supported_resources,
            guideline=guideline
        )

    def scan_resource_conf(self, conf, entity_type):
        """
        Validates the resource configuration.

        Args:
            conf: Resource configuration dictionary
            entity_type: The terraform resource type being checked

        Returns:
            CheckResult.PASSED or CheckResult.FAILED
        """
        # Your validation logic here
        if meets_requirement:
            return CheckResult.PASSED
        return CheckResult.FAILED

# Instantiate the check
check_your_new_policy = YourNewPolicySOC2()
```

### Step 2: Understanding Resource Configuration

Terraform resources are parsed into dictionaries. Here's how to access values:

```python
# Simple attribute
encrypted = conf.get('encrypted', [False])[0]

# Nested block
settings = conf.get('settings', [])
if settings:
    for setting in settings:
        tier = setting.get('tier', [''])[0]

# List attribute
cidr_blocks = conf.get('cidr_blocks', [])
for cidr_list in cidr_blocks:
    if '0.0.0.0/0' in cidr_list:
        return CheckResult.FAILED
```

### Step 3: Common Patterns

#### Pattern 1: Boolean Check
```python
def scan_resource_conf(self, conf, entity_type):
    enabled = conf.get('enabled', [False])[0]
    if enabled:
        return CheckResult.PASSED
    return CheckResult.FAILED
```

#### Pattern 2: Threshold Check
```python
def scan_resource_conf(self, conf, entity_type):
    retention_days = conf.get('retention_days', [0])[0]
    if retention_days >= 90:
        return CheckResult.PASSED
    return CheckResult.FAILED
```

#### Pattern 3: Multiple Resource Types
```python
def scan_resource_conf(self, conf, entity_type):
    if entity_type == 'aws_s3_bucket':
        # Check for old-style configuration
        if 'versioning' in conf:
            return CheckResult.PASSED

    if entity_type == 'aws_s3_bucket_versioning':
        # Check for new-style configuration
        versioning_config = conf.get('versioning_configuration', [])
        if versioning_config:
            return CheckResult.PASSED

    return CheckResult.FAILED
```

#### Pattern 4: List Validation
```python
def scan_resource_conf(self, conf, entity_type):
    members = conf.get('members', [])
    for member_list in members:
        if isinstance(member_list, list):
            for member in member_list:
                if member in ['allUsers', 'allAuthenticatedUsers']:
                    return CheckResult.FAILED
    return CheckResult.PASSED
```

## Testing Your Policy

### 1. Create Test Terraform Files

Create both passing and failing examples:

**Passing Example:**
```hcl
# examples/terraform/test_compliant.tf
resource "aws_s3_bucket" "test_pass" {
  bucket = "test-bucket"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "test_pass" {
  bucket = aws_s3_bucket.test_pass.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}
```

**Failing Example:**
```hcl
# examples/terraform/test_non_compliant.tf
resource "aws_s3_bucket" "test_fail" {
  bucket = "test-bucket"
  # No encryption configured
}
```

### 2. Run Checkov

```bash
# Test passing configuration
checkov -f examples/terraform/test_compliant.tf \
    --external-checks-dir ./checkov_policies \
    --check CKV_SOC2_AWS_XXX

# Test failing configuration
checkov -f examples/terraform/test_non_compliant.tf \
    --external-checks-dir ./checkov_policies \
    --check CKV_SOC2_AWS_XXX
```

### 3. Verify Results

- Passing config should show: `PASSED for resource`
- Failing config should show: `FAILED for resource`
- Guideline should be clear and actionable

## Code Style

### Python Style
- Follow PEP 8
- Use clear, descriptive variable names
- Add comments for complex logic
- Keep methods focused and concise

### Documentation
- Clear policy name describing what is checked
- Actionable guideline explaining how to comply
- SOC2 control reference in comments

### Example with Best Practices

```python
class S3BucketEncryptionSOC2(BaseResourceCheck):
    """
    Ensures S3 buckets have server-side encryption enabled.

    SOC2 Control: CC6.6 - Encryption of Data at Rest

    This check validates both the legacy s3_bucket encryption configuration
    and the newer separate encryption_configuration resource.
    """

    def __init__(self):
        name = "Ensure S3 bucket has server-side encryption enabled (SOC2)"
        id = "CKV_SOC2_AWS_001"
        supported_resources = [
            'aws_s3_bucket',
            'aws_s3_bucket_server_side_encryption_configuration'
        ]
        categories = [CheckCategories.ENCRYPTION]
        guideline = (
            "SOC2 requires encryption of data at rest. "
            "Enable S3 bucket server-side encryption using AES256 or KMS."
        )
        super().__init__(
            name=name,
            id=id,
            categories=categories,
            supported_resources=supported_resources,
            guideline=guideline
        )

    def scan_resource_conf(self, conf, entity_type):
        # Handle separate encryption configuration resource (AWS provider >= 4.0)
        if entity_type == 'aws_s3_bucket_server_side_encryption_configuration':
            if 'rule' in conf:
                return CheckResult.PASSED

        # Handle legacy inline encryption configuration (AWS provider < 4.0)
        if entity_type == 'aws_s3_bucket':
            if 'server_side_encryption_configuration' in conf:
                return CheckResult.PASSED

        # No encryption configuration found
        return CheckResult.FAILED

# Always instantiate the check at module level
check_s3_encryption = S3BucketEncryptionSOC2()
```

## Submission Process

### 1. Before Submitting

- [ ] Policy follows naming convention
- [ ] Policy has clear name and guideline
- [ ] Code is well-commented
- [ ] Tested with passing and failing examples
- [ ] Added to appropriate policy file
- [ ] Updated POLICY_INDEX.md with new policy
- [ ] Updated README.md if adding new category

### 2. Documentation Updates

When adding a policy, update:

1. **POLICY_INDEX.md**: Add entry in appropriate table
2. **README.md**: Update policy count
3. **Example files**: Add compliant/non-compliant examples

### 3. Create Pull Request

Include in your PR description:
- SOC2 control this addresses
- Why this policy is needed
- Example passing configuration
- Example failing configuration
- Testing performed

## Advanced Topics

### Handling Multiple Conditions

```python
def scan_resource_conf(self, conf, entity_type):
    # All conditions must be met
    condition1 = conf.get('encrypted', [False])[0]
    condition2 = conf.get('kms_key_id')
    condition3 = conf.get('backup_retention_period', [0])[0] >= 7

    if condition1 and condition2 and condition3:
        return CheckResult.PASSED

    return CheckResult.FAILED
```

### Handling Edge Cases

```python
def scan_resource_conf(self, conf, entity_type):
    # Handle optional configuration
    backup_config = conf.get('backup_configuration')
    if not backup_config:
        # No backup config means not compliant
        return CheckResult.FAILED

    # Safely navigate nested structures
    for config in backup_config:
        enabled = config.get('enabled', [False])[0]
        retention = config.get('retention_days', [0])[0]

        if enabled and retention >= 7:
            return CheckResult.PASSED

    return CheckResult.FAILED
```

### Supporting Multiple Providers

```python
# For multi-cloud resources that share similar patterns
class DatabaseEncryptionSOC2(BaseResourceCheck):
    def __init__(self):
        name = "Ensure database has encryption enabled (SOC2)"
        id = "CKV_SOC2_MULTI_001"
        supported_resources = [
            'aws_db_instance',
            'google_sql_database_instance',
            'digitalocean_database_cluster'
        ]
        categories = [CheckCategories.ENCRYPTION]
        guideline = "SOC2 requires encryption of data at rest."
        super().__init__(name=name, id=id, categories=categories,
                        supported_resources=supported_resources, guideline=guideline)

    def scan_resource_conf(self, conf, entity_type):
        if entity_type == 'aws_db_instance':
            return CheckResult.PASSED if conf.get('storage_encrypted', [False])[0] else CheckResult.FAILED

        if entity_type == 'google_sql_database_instance':
            return CheckResult.PASSED if conf.get('encryption_key_name') else CheckResult.FAILED

        if entity_type == 'digitalocean_database_cluster':
            # DO encrypts by default
            return CheckResult.PASSED

        return CheckResult.FAILED
```

## Questions?

- Review existing policies in `checkov_policies/` for examples
- Check Checkov documentation: https://www.checkov.io/
- Open an issue for questions or clarifications

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
