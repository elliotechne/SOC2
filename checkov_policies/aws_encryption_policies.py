"""
SOC2 Encryption Policies for AWS Terraform Resources
Covers: Data encryption at rest and in transit
"""

from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck
from checkov.common.models.enums import CheckResult, CheckCategories


class S3BucketEncryptionSOC2(BaseResourceCheck):
    def __init__(self):
        name = "Ensure S3 bucket has server-side encryption enabled (SOC2)"
        id = "CKV_SOC2_AWS_001"
        supported_resources = ['aws_s3_bucket', 'aws_s3_bucket_server_side_encryption_configuration']
        categories = [CheckCategories.ENCRYPTION]
        guideline = "SOC2 requires encryption of data at rest. Enable S3 bucket encryption."
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources, guideline=guideline)

    def scan_resource_conf(self, conf, entity_type):
        if entity_type == 'aws_s3_bucket_server_side_encryption_configuration':
            if 'rule' in conf:
                return CheckResult.PASSED

        if entity_type == 'aws_s3_bucket':
            if 'server_side_encryption_configuration' in conf:
                return CheckResult.PASSED

        return CheckResult.FAILED


class EBSVolumeEncryptionSOC2(BaseResourceCheck):
    def __init__(self):
        name = "Ensure EBS volumes are encrypted (SOC2)"
        id = "CKV_SOC2_AWS_002"
        supported_resources = ['aws_ebs_volume', 'aws_instance']
        categories = [CheckCategories.ENCRYPTION]
        guideline = "SOC2 requires encryption of data at rest. Enable EBS volume encryption."
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources, guideline=guideline)

    def scan_resource_conf(self, conf, entity_type):
        if entity_type == 'aws_ebs_volume':
            if conf.get('encrypted', [False])[0] is True:
                return CheckResult.PASSED

        if entity_type == 'aws_instance':
            ebs_block_devices = conf.get('ebs_block_device', [])
            if ebs_block_devices:
                for device in ebs_block_devices:
                    if not device.get('encrypted', [False])[0]:
                        return CheckResult.FAILED
                return CheckResult.PASSED
            root_block_device = conf.get('root_block_device', [])
            if root_block_device:
                for device in root_block_device:
                    if device.get('encrypted', [False])[0] is True:
                        return CheckResult.PASSED

        return CheckResult.FAILED


class RDSEncryptionSOC2(BaseResourceCheck):
    def __init__(self):
        name = "Ensure RDS instances are encrypted (SOC2)"
        id = "CKV_SOC2_AWS_003"
        supported_resources = ['aws_db_instance', 'aws_rds_cluster']
        categories = [CheckCategories.ENCRYPTION]
        guideline = "SOC2 requires encryption of data at rest. Enable RDS encryption."
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources, guideline=guideline)

    def scan_resource_conf(self, conf, entity_type):
        if conf.get('storage_encrypted', [False])[0] is True:
            return CheckResult.PASSED
        return CheckResult.FAILED


class EFSEncryptionSOC2(BaseResourceCheck):
    def __init__(self):
        name = "Ensure EFS file systems are encrypted (SOC2)"
        id = "CKV_SOC2_AWS_004"
        supported_resources = ['aws_efs_file_system']
        categories = [CheckCategories.ENCRYPTION]
        guideline = "SOC2 requires encryption of data at rest. Enable EFS encryption."
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources, guideline=guideline)

    def scan_resource_conf(self, conf, entity_type):
        if conf.get('encrypted', [False])[0] is True:
            return CheckResult.PASSED
        return CheckResult.FAILED


class ALBListenerEncryptionSOC2(BaseResourceCheck):
    def __init__(self):
        name = "Ensure ALB listeners use HTTPS/TLS for data in transit (SOC2)"
        id = "CKV_SOC2_AWS_005"
        supported_resources = ['aws_lb_listener', 'aws_alb_listener']
        categories = [CheckCategories.ENCRYPTION]
        guideline = "SOC2 requires encryption of data in transit. Use HTTPS/TLS for load balancer listeners."
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources, guideline=guideline)

    def scan_resource_conf(self, conf, entity_type):
        protocol = conf.get('protocol', [''])[0]
        if protocol in ['HTTPS', 'TLS']:
            return CheckResult.PASSED
        return CheckResult.FAILED


class RedshiftEncryptionSOC2(BaseResourceCheck):
    def __init__(self):
        name = "Ensure Redshift clusters are encrypted (SOC2)"
        id = "CKV_SOC2_AWS_006"
        supported_resources = ['aws_redshift_cluster']
        categories = [CheckCategories.ENCRYPTION]
        guideline = "SOC2 requires encryption of data at rest. Enable Redshift encryption."
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources, guideline=guideline)

    def scan_resource_conf(self, conf, entity_type):
        if conf.get('encrypted', [False])[0] is True:
            return CheckResult.PASSED
        return CheckResult.FAILED


class DynamoDBEncryptionSOC2(BaseResourceCheck):
    def __init__(self):
        name = "Ensure DynamoDB tables use encryption (SOC2)"
        id = "CKV_SOC2_AWS_007"
        supported_resources = ['aws_dynamodb_table']
        categories = [CheckCategories.ENCRYPTION]
        guideline = "SOC2 requires encryption of data at rest. Enable DynamoDB encryption."
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources, guideline=guideline)

    def scan_resource_conf(self, conf, entity_type):
        server_side_encryption = conf.get('server_side_encryption')
        if server_side_encryption and server_side_encryption[0].get('enabled', [False])[0] is True:
            return CheckResult.PASSED
        return CheckResult.FAILED


check_s3_encryption = S3BucketEncryptionSOC2()
check_ebs_encryption = EBSVolumeEncryptionSOC2()
check_rds_encryption = RDSEncryptionSOC2()
check_efs_encryption = EFSEncryptionSOC2()
check_alb_encryption = ALBListenerEncryptionSOC2()
check_redshift_encryption = RedshiftEncryptionSOC2()
check_dynamodb_encryption = DynamoDBEncryptionSOC2()
