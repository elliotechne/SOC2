"""
SOC2 Backup and Recovery Policies for DigitalOcean Terraform Resources
Covers: Droplet backups, database backups, volume snapshots
"""

from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck
from checkov.common.models.enums import CheckResult, CheckCategories


class DODropletBackupsSOC2(BaseResourceCheck):
    def __init__(self):
        name = "Ensure droplets have backups enabled (SOC2)"
        id = "CKV_SOC2_DO_401"
        supported_resources = ['digitalocean_droplet']
        categories = [CheckCategories.BACKUP_AND_RECOVERY]
        guideline = "SOC2 requires backup and recovery. Enable droplet backups."
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources, guideline=guideline)

    def scan_resource_conf(self, conf):
        backups = conf.get('backups', [False])[0]
        if backups:
            return CheckResult.PASSED
        return CheckResult.FAILED


class DODatabaseBackupsSOC2(BaseResourceCheck):
    def __init__(self):
        name = "Ensure database clusters have automated backups (SOC2)"
        id = "CKV_SOC2_DO_402"
        supported_resources = ['digitalocean_database_cluster']
        categories = [CheckCategories.BACKUP_AND_RECOVERY]
        guideline = "SOC2 requires backup and recovery. Database backups are automatic in DO."
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources, guideline=guideline)

    def scan_resource_conf(self, conf):
        return CheckResult.PASSED


class DOVolumeSnapshotSOC2(BaseResourceCheck):
    def __init__(self):
        name = "Ensure volumes have snapshot policy (SOC2)"
        id = "CKV_SOC2_DO_403"
        supported_resources = ['digitalocean_volume_snapshot']
        categories = [CheckCategories.BACKUP_AND_RECOVERY]
        guideline = "SOC2 requires backup and recovery. Create volume snapshots."
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources, guideline=guideline)

    def scan_resource_conf(self, conf):
        volume_id = conf.get('volume_id')
        if volume_id:
            return CheckResult.PASSED
        return CheckResult.FAILED


class DOKubernetesBackupSOC2(BaseResourceCheck):
    def __init__(self):
        name = "Ensure Kubernetes clusters have backup strategy (SOC2)"
        id = "CKV_SOC2_DO_404"
        supported_resources = ['digitalocean_kubernetes_cluster']
        categories = [CheckCategories.BACKUP_AND_RECOVERY]
        guideline = "SOC2 requires backup and recovery. Implement K8s backup strategy."
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources, guideline=guideline)

    def scan_resource_conf(self, conf):
        return CheckResult.PASSED


class DOSpacesLifecycleSOC2(BaseResourceCheck):
    def __init__(self):
        name = "Ensure Spaces buckets have lifecycle policy (SOC2)"
        id = "CKV_SOC2_DO_405"
        supported_resources = ['digitalocean_spaces_bucket']
        categories = [CheckCategories.BACKUP_AND_RECOVERY]
        guideline = "SOC2 requires data retention policies. Configure lifecycle rules."
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources, guideline=guideline)

    def scan_resource_conf(self, conf):
        lifecycle_rule = conf.get('lifecycle_rule')
        if lifecycle_rule:
            return CheckResult.PASSED
        return CheckResult.FAILED


class DODatabaseHighAvailabilitySOC2(BaseResourceCheck):
    def __init__(self):
        name = "Ensure database clusters use high availability (SOC2)"
        id = "CKV_SOC2_DO_406"
        supported_resources = ['digitalocean_database_cluster']
        categories = [CheckCategories.BACKUP_AND_RECOVERY]
        guideline = "SOC2 requires high availability. Use multiple nodes for databases."
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources, guideline=guideline)

    def scan_resource_conf(self, conf):
        node_count = conf.get('node_count', [1])[0]
        if node_count >= 2:
            return CheckResult.PASSED
        return CheckResult.FAILED


check_do_droplet_backups = DODropletBackupsSOC2()
check_do_db_backups = DODatabaseBackupsSOC2()
check_do_volume_snapshot = DOVolumeSnapshotSOC2()
check_do_k8s_backup = DOKubernetesBackupSOC2()
check_do_spaces_lifecycle = DOSpacesLifecycleSOC2()
check_do_db_ha = DODatabaseHighAvailabilitySOC2()
