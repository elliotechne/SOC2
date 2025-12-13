"""
SOC2 Backup and Recovery Policies for AWS Terraform Resources
Covers: Backup plans, RDS backups, versioning, disaster recovery
"""

from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck
from checkov.common.models.enums import CheckResult, CheckCategories


class RDSBackupRetentionSOC2(BaseResourceCheck):
    def __init__(self):
        name = "Ensure RDS instances have adequate backup retention (SOC2)"
        id = "CKV_SOC2_AWS_401"
        supported_resources = ['aws_db_instance', 'aws_rds_cluster']
        categories = [CheckCategories.BACKUP_AND_RECOVERY]
        guideline = "SOC2 requires backup and recovery. Set RDS backup retention >= 7 days."
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources, guideline=guideline)

    def scan_resource_conf(self, conf, entity_type):
        backup_retention_period = conf.get('backup_retention_period', [0])[0]
        if backup_retention_period >= 7:
            return CheckResult.PASSED
        return CheckResult.FAILED


class S3VersioningEnabledSOC2(BaseResourceCheck):
    def __init__(self):
        name = "Ensure S3 buckets have versioning enabled (SOC2)"
        id = "CKV_SOC2_AWS_402"
        supported_resources = ['aws_s3_bucket', 'aws_s3_bucket_versioning']
        categories = [CheckCategories.BACKUP_AND_RECOVERY]
        guideline = "SOC2 requires data protection. Enable S3 bucket versioning."
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources, guideline=guideline)

    def scan_resource_conf(self, conf, entity_type):
        if entity_type == 'aws_s3_bucket_versioning':
            versioning_configuration = conf.get('versioning_configuration', [])
            if versioning_configuration:
                for config in versioning_configuration:
                    status = config.get('status', [''])[0]
                    if status == 'Enabled':
                        return CheckResult.PASSED

        if entity_type == 'aws_s3_bucket':
            versioning = conf.get('versioning', [])
            if versioning:
                for config in versioning:
                    enabled = config.get('enabled', [False])[0]
                    if enabled:
                        return CheckResult.PASSED

        return CheckResult.FAILED


class DynamoDBBackupSOC2(BaseResourceCheck):
    def __init__(self):
        name = "Ensure DynamoDB tables have point-in-time recovery (SOC2)"
        id = "CKV_SOC2_AWS_403"
        supported_resources = ['aws_dynamodb_table']
        categories = [CheckCategories.BACKUP_AND_RECOVERY]
        guideline = "SOC2 requires backup and recovery. Enable PITR for DynamoDB."
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources, guideline=guideline)

    def scan_resource_conf(self, conf, entity_type):
        point_in_time_recovery = conf.get('point_in_time_recovery')
        if point_in_time_recovery and point_in_time_recovery[0].get('enabled', [False])[0]:
            return CheckResult.PASSED
        return CheckResult.FAILED


class EBSSnapshotSOC2(BaseResourceCheck):
    def __init__(self):
        name = "Ensure EBS volumes have snapshot lifecycle policy (SOC2)"
        id = "CKV_SOC2_AWS_404"
        supported_resources = ['aws_dlm_lifecycle_policy']
        categories = [CheckCategories.BACKUP_AND_RECOVERY]
        guideline = "SOC2 requires backup and recovery. Create EBS snapshot policies."
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources, guideline=guideline)

    def scan_resource_conf(self, conf, entity_type):
        policy_details = conf.get('policy_details')
        if policy_details:
            return CheckResult.PASSED
        return CheckResult.FAILED


class BackupVaultEnabledSOC2(BaseResourceCheck):
    def __init__(self):
        name = "Ensure AWS Backup vault is configured (SOC2)"
        id = "CKV_SOC2_AWS_405"
        supported_resources = ['aws_backup_vault']
        categories = [CheckCategories.BACKUP_AND_RECOVERY]
        guideline = "SOC2 requires backup strategy. Configure AWS Backup vaults."
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources, guideline=guideline)

    def scan_resource_conf(self, conf, entity_type):
        name = conf.get('name')
        if name:
            return CheckResult.PASSED
        return CheckResult.FAILED


class BackupPlanEnabledSOC2(BaseResourceCheck):
    def __init__(self):
        name = "Ensure AWS Backup plan is configured (SOC2)"
        id = "CKV_SOC2_AWS_406"
        supported_resources = ['aws_backup_plan']
        categories = [CheckCategories.BACKUP_AND_RECOVERY]
        guideline = "SOC2 requires backup strategy. Configure backup plans."
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources, guideline=guideline)

    def scan_resource_conf(self, conf, entity_type):
        rule = conf.get('rule')
        if rule and len(rule) > 0:
            return CheckResult.PASSED
        return CheckResult.FAILED


class RDSMultiAZSOC2(BaseResourceCheck):
    def __init__(self):
        name = "Ensure RDS instances use Multi-AZ for high availability (SOC2)"
        id = "CKV_SOC2_AWS_407"
        supported_resources = ['aws_db_instance']
        categories = [CheckCategories.BACKUP_AND_RECOVERY]
        guideline = "SOC2 requires high availability. Enable Multi-AZ for RDS."
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources, guideline=guideline)

    def scan_resource_conf(self, conf, entity_type):
        multi_az = conf.get('multi_az', [False])[0]
        if multi_az:
            return CheckResult.PASSED
        return CheckResult.FAILED


check_rds_backup_retention = RDSBackupRetentionSOC2()
check_s3_versioning = S3VersioningEnabledSOC2()
check_dynamodb_backup = DynamoDBBackupSOC2()
check_ebs_snapshot = EBSSnapshotSOC2()
check_backup_vault = BackupVaultEnabledSOC2()
check_backup_plan = BackupPlanEnabledSOC2()
check_rds_multi_az = RDSMultiAZSOC2()
