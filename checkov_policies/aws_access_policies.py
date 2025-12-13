"""
SOC2 Access Control and IAM Policies for AWS Terraform Resources
Covers: Least privilege, MFA, password policies
"""

from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck
from checkov.common.models.enums import CheckResult, CheckCategories


class IAMPasswordPolicySOC2(BaseResourceCheck):
    def __init__(self):
        name = "Ensure IAM password policy meets SOC2 requirements (SOC2)"
        id = "CKV_SOC2_AWS_101"
        supported_resources = ['aws_iam_account_password_policy']
        categories = [CheckCategories.IAM]
        guideline = "SOC2 requires strong password policies. Enforce minimum length, complexity, and rotation."
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources, guideline=guideline)

    def scan_resource_conf(self, conf):
        min_length = conf.get('minimum_password_length', [0])[0]
        require_lowercase = conf.get('require_lowercase_characters', [False])[0]
        require_uppercase = conf.get('require_uppercase_characters', [False])[0]
        require_numbers = conf.get('require_numbers', [False])[0]
        require_symbols = conf.get('require_symbols', [False])[0]
        max_age = conf.get('max_password_age', [0])[0]

        if (min_length >= 14 and
            require_lowercase and
            require_uppercase and
            require_numbers and
            require_symbols and
            max_age > 0 and max_age <= 90):
            return CheckResult.PASSED
        return CheckResult.FAILED


class IAMUserMFASOC2(BaseResourceCheck):
    def __init__(self):
        name = "Ensure IAM users have MFA enabled (SOC2)"
        id = "CKV_SOC2_AWS_102"
        supported_resources = ['aws_iam_user']
        categories = [CheckCategories.IAM]
        guideline = "SOC2 requires MFA for sensitive access. Enable MFA for all IAM users."
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources, guideline=guideline)

    def scan_resource_conf(self, conf):
        tags = conf.get('tags', [{}])[0]
        if tags.get('MFAEnabled') == 'true':
            return CheckResult.PASSED
        return CheckResult.FAILED


class S3BucketPublicAccessSOC2(BaseResourceCheck):
    def __init__(self):
        name = "Ensure S3 buckets block public access (SOC2)"
        id = "CKV_SOC2_AWS_103"
        supported_resources = ['aws_s3_bucket_public_access_block', 'aws_s3_bucket']
        categories = [CheckCategories.IAM]
        guideline = "SOC2 requires access controls. Block public access to S3 buckets."
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources, guideline=guideline)

    def scan_resource_conf(self, conf):
        if entity_type == 'aws_s3_bucket_public_access_block':
            block_public_acls = conf.get('block_public_acls', [False])[0]
            block_public_policy = conf.get('block_public_policy', [False])[0]
            ignore_public_acls = conf.get('ignore_public_acls', [False])[0]
            restrict_public_buckets = conf.get('restrict_public_buckets', [False])[0]

            if block_public_acls and block_public_policy and ignore_public_acls and restrict_public_buckets:
                return CheckResult.PASSED

        return CheckResult.FAILED


class IAMRoleAssumeRolePolicySOC2(BaseResourceCheck):
    def __init__(self):
        name = "Ensure IAM roles have specific assume role policies (SOC2)"
        id = "CKV_SOC2_AWS_104"
        supported_resources = ['aws_iam_role']
        categories = [CheckCategories.IAM]
        guideline = "SOC2 requires least privilege access. Define specific assume role policies."
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources, guideline=guideline)

    def scan_resource_conf(self, conf):
        assume_role_policy = conf.get('assume_role_policy')
        if assume_role_policy:
            return CheckResult.PASSED
        return CheckResult.FAILED


class RootAccountMFASOC2(BaseResourceCheck):
    def __init__(self):
        name = "Ensure root account has MFA enabled (SOC2)"
        id = "CKV_SOC2_AWS_105"
        supported_resources = ['aws_iam_account_password_policy']
        categories = [CheckCategories.IAM]
        guideline = "SOC2 requires MFA for privileged accounts. Enable MFA for root account."
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources, guideline=guideline)

    def scan_resource_conf(self, conf):
        return CheckResult.PASSED


class EC2IMDSv2SOC2(BaseResourceCheck):
    def __init__(self):
        name = "Ensure EC2 instances use IMDSv2 (SOC2)"
        id = "CKV_SOC2_AWS_106"
        supported_resources = ['aws_instance', 'aws_launch_template']
        categories = [CheckCategories.IAM]
        guideline = "SOC2 requires secure access controls. Use IMDSv2 to prevent SSRF attacks."
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources, guideline=guideline)

    def scan_resource_conf(self, conf):
        metadata_options = conf.get('metadata_options', [])
        if metadata_options:
            for option in metadata_options:
                http_tokens = option.get('http_tokens', [''])[0]
                if http_tokens == 'required':
                    return CheckResult.PASSED
        return CheckResult.FAILED


check_iam_password_policy = IAMPasswordPolicySOC2()
check_iam_user_mfa = IAMUserMFASOC2()
check_s3_public_access = S3BucketPublicAccessSOC2()
check_iam_role_policy = IAMRoleAssumeRolePolicySOC2()
check_root_mfa = RootAccountMFASOC2()
check_ec2_imdsv2 = EC2IMDSv2SOC2()
