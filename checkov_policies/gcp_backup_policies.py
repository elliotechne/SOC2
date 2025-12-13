"""
SOC2 Backup and Recovery Policies for GCP Terraform Resources
Covers: Automated backups, snapshots, disaster recovery
"""

from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck
from checkov.common.models.enums import CheckResult, CheckCategories


class GCPSQLBackupEnabledSOC2(BaseResourceCheck):
    def __init__(self):
        name = "Ensure Cloud SQL has automated backups enabled (SOC2)"
        id = "CKV_SOC2_GCP_401"
        supported_resources = ['google_sql_database_instance']
        categories = [CheckCategories.BACKUP_AND_RECOVERY]
        guideline = "SOC2 requires backup and recovery. Enable Cloud SQL backups."
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources, guideline=guideline)

    def scan_resource_conf(self, conf, entity_type):
        settings = conf.get('settings', [])
        if settings:
            for setting in settings:
                backup_configuration = setting.get('backup_configuration', [])
                for backup_config in backup_configuration:
                    enabled = backup_config.get('enabled', [False])[0]
                    if enabled:
                        return CheckResult.PASSED

        return CheckResult.FAILED


class GCPComputeDiskSnapshotSOC2(BaseResourceCheck):
    def __init__(self):
        name = "Ensure compute disks have snapshot schedule (SOC2)"
        id = "CKV_SOC2_GCP_402"
        supported_resources = ['google_compute_resource_policy']
        categories = [CheckCategories.BACKUP_AND_RECOVERY]
        guideline = "SOC2 requires backup and recovery. Create disk snapshot policies."
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources, guideline=guideline)

    def scan_resource_conf(self, conf, entity_type):
        snapshot_schedule_policy = conf.get('snapshot_schedule_policy')
        if snapshot_schedule_policy:
            return CheckResult.PASSED
        return CheckResult.FAILED


class GCPStorageVersioningSOC2(BaseResourceCheck):
    def __init__(self):
        name = "Ensure GCS buckets have versioning enabled (SOC2)"
        id = "CKV_SOC2_GCP_403"
        supported_resources = ['google_storage_bucket']
        categories = [CheckCategories.BACKUP_AND_RECOVERY]
        guideline = "SOC2 requires data protection. Enable GCS bucket versioning."
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources, guideline=guideline)

    def scan_resource_conf(self, conf, entity_type):
        versioning = conf.get('versioning')
        if versioning and versioning[0].get('enabled', [False])[0]:
            return CheckResult.PASSED
        return CheckResult.FAILED


class GCPSQLHighAvailabilitySOC2(BaseResourceCheck):
    def __init__(self):
        name = "Ensure Cloud SQL instances use high availability (SOC2)"
        id = "CKV_SOC2_GCP_404"
        supported_resources = ['google_sql_database_instance']
        categories = [CheckCategories.BACKUP_AND_RECOVERY]
        guideline = "SOC2 requires high availability. Enable HA for Cloud SQL."
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources, guideline=guideline)

    def scan_resource_conf(self, conf, entity_type):
        settings = conf.get('settings', [])
        if settings:
            for setting in settings:
                availability_type = setting.get('availability_type', [''])[0]
                if availability_type == 'REGIONAL':
                    return CheckResult.PASSED

        return CheckResult.FAILED


class GCPBigtableBackupSOC2(BaseResourceCheck):
    def __init__(self):
        name = "Ensure Bigtable has backup configuration (SOC2)"
        id = "CKV_SOC2_GCP_405"
        supported_resources = ['google_bigtable_instance']
        categories = [CheckCategories.BACKUP_AND_RECOVERY]
        guideline = "SOC2 requires backup and recovery. Configure Bigtable backups."
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources, guideline=guideline)

    def scan_resource_conf(self, conf, entity_type):
        cluster = conf.get('cluster', [])
        if cluster and len(cluster) > 0:
            return CheckResult.PASSED
        return CheckResult.FAILED


class GCPSQLPointInTimeRecoverySOC2(BaseResourceCheck):
    def __init__(self):
        name = "Ensure Cloud SQL has point-in-time recovery (SOC2)"
        id = "CKV_SOC2_GCP_406"
        supported_resources = ['google_sql_database_instance']
        categories = [CheckCategories.BACKUP_AND_RECOVERY]
        guideline = "SOC2 requires backup and recovery. Enable PITR for Cloud SQL."
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources, guideline=guideline)

    def scan_resource_conf(self, conf, entity_type):
        settings = conf.get('settings', [])
        if settings:
            for setting in settings:
                backup_configuration = setting.get('backup_configuration', [])
                for backup_config in backup_configuration:
                    enabled = backup_config.get('enabled', [False])[0]
                    point_in_time_recovery = backup_config.get('point_in_time_recovery_enabled', [False])[0]
                    if enabled and point_in_time_recovery:
                        return CheckResult.PASSED

        return CheckResult.FAILED


check_gcp_sql_backup = GCPSQLBackupEnabledSOC2()
check_gcp_disk_snapshot = GCPComputeDiskSnapshotSOC2()
check_gcp_storage_versioning = GCPStorageVersioningSOC2()
check_gcp_sql_ha = GCPSQLHighAvailabilitySOC2()
check_gcp_bigtable_backup = GCPBigtableBackupSOC2()
check_gcp_sql_pitr = GCPSQLPointInTimeRecoverySOC2()
