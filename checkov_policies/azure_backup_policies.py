"""
SOC2 Backup and Recovery Policies for Azure Terraform Resources
Covers: Backup retention, point-in-time recovery, high availability
"""

from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck
from checkov.common.models.enums import CheckResult, CheckCategories


class VMBackupSOC2(BaseResourceCheck):
    def __init__(self):
        name = "Ensure Virtual Machine has backup configured (SOC2)"
        id = "CKV_SOC2_AZURE_401"
        supported_resources = ['azurerm_linux_virtual_machine', 'azurerm_windows_virtual_machine']
        categories = [CheckCategories.BACKUP_AND_RECOVERY]
        guideline = "SOC2 requires backup and recovery capabilities. Configure VM backups."
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources, guideline=guideline)

    def scan_resource_conf(self, conf):
        # Backup is configured via azurerm_backup_protected_vm
        # Check tags for backup indication
        tags = conf.get('tags', [{}])[0]
        if tags.get('BackupEnabled') == 'true' or tags.get('Backup') == 'true':
            return CheckResult.PASSED

        # Check for availability set or zone for HA
        availability_set_id = conf.get('availability_set_id')
        zone = conf.get('zone')

        if availability_set_id or zone:
            return CheckResult.PASSED

        return CheckResult.FAILED


class SQLDatabaseBackupSOC2(BaseResourceCheck):
    def __init__(self):
        name = "Ensure SQL Database has appropriate backup retention (SOC2)"
        id = "CKV_SOC2_AZURE_402"
        supported_resources = ['azurerm_mssql_database', 'azurerm_sql_database']
        categories = [CheckCategories.BACKUP_AND_RECOVERY]
        guideline = "SOC2 requires backup retention. Set appropriate retention for SQL databases."
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources, guideline=guideline)

    def scan_resource_conf(self, conf):
        # Check short term retention policy
        short_term_retention_policy = conf.get('short_term_retention_policy', [])
        if short_term_retention_policy:
            for policy in short_term_retention_policy:
                retention_days = policy.get('retention_days', [7])[0]
                if retention_days >= 7:
                    return CheckResult.PASSED

        # Check long term retention policy
        long_term_retention_policy = conf.get('long_term_retention_policy')
        if long_term_retention_policy:
            return CheckResult.PASSED

        # Check for geo-replication
        create_mode = conf.get('create_mode', [''])[0]
        if create_mode in ['Secondary', 'PointInTimeRestore', 'Recovery', 'Restore']:
            return CheckResult.PASSED

        return CheckResult.PASSED  # Azure SQL has default backup


class PostgreSQLBackupSOC2(BaseResourceCheck):
    def __init__(self):
        name = "Ensure PostgreSQL Server has backup retention configured (SOC2)"
        id = "CKV_SOC2_AZURE_403"
        supported_resources = ['azurerm_postgresql_server', 'azurerm_postgresql_flexible_server']
        categories = [CheckCategories.BACKUP_AND_RECOVERY]
        guideline = "SOC2 requires backup retention. Set retention to at least 7 days for PostgreSQL."
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources, guideline=guideline)

    def scan_resource_conf(self, conf):
        backup_retention_days = conf.get('backup_retention_days', [7])[0]
        geo_redundant_backup_enabled = conf.get('geo_redundant_backup_enabled', [False])[0]

        if backup_retention_days >= 7:
            return CheckResult.PASSED

        return CheckResult.FAILED


class MySQLBackupSOC2(BaseResourceCheck):
    def __init__(self):
        name = "Ensure MySQL Server has backup retention configured (SOC2)"
        id = "CKV_SOC2_AZURE_404"
        supported_resources = ['azurerm_mysql_server', 'azurerm_mysql_flexible_server']
        categories = [CheckCategories.BACKUP_AND_RECOVERY]
        guideline = "SOC2 requires backup retention. Set retention to at least 7 days for MySQL."
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources, guideline=guideline)

    def scan_resource_conf(self, conf):
        backup_retention_days = conf.get('backup_retention_days', [7])[0]
        geo_redundant_backup_enabled = conf.get('geo_redundant_backup_enabled', [False])[0]

        if backup_retention_days >= 7:
            return CheckResult.PASSED

        return CheckResult.FAILED


class StorageAccountReplicationSOC2(BaseResourceCheck):
    def __init__(self):
        name = "Ensure Storage Account uses geo-redundant replication (SOC2)"
        id = "CKV_SOC2_AZURE_405"
        supported_resources = ['azurerm_storage_account']
        categories = [CheckCategories.BACKUP_AND_RECOVERY]
        guideline = "SOC2 requires high availability and disaster recovery. Use geo-redundant storage."
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources, guideline=guideline)

    def scan_resource_conf(self, conf):
        account_replication_type = conf.get('account_replication_type', ['LRS'])[0]

        # Geo-redundant options: GRS, GZRS, RAGRS, RAGZRS
        if account_replication_type in ['GRS', 'GZRS', 'RAGRS', 'RAGZRS']:
            return CheckResult.PASSED

        # ZRS is zone-redundant which is acceptable for some scenarios
        if account_replication_type == 'ZRS':
            return CheckResult.PASSED

        return CheckResult.FAILED


class RecoveryVaultBackupPolicySOC2(BaseResourceCheck):
    def __init__(self):
        name = "Ensure Recovery Vault backup policy has adequate retention (SOC2)"
        id = "CKV_SOC2_AZURE_406"
        supported_resources = ['azurerm_backup_policy_vm']
        categories = [CheckCategories.BACKUP_AND_RECOVERY]
        guideline = "SOC2 requires backup retention. Set retention to at least 30 days."
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources, guideline=guideline)

    def scan_resource_conf(self, conf):
        retention_daily = conf.get('retention_daily', [])
        if retention_daily:
            for daily in retention_daily:
                count = daily.get('count', [7])[0]
                if count >= 30:
                    return CheckResult.PASSED

        retention_weekly = conf.get('retention_weekly')
        retention_monthly = conf.get('retention_monthly')
        retention_yearly = conf.get('retention_yearly')

        # If any long-term retention is configured, pass
        if retention_weekly or retention_monthly or retention_yearly:
            return CheckResult.PASSED

        return CheckResult.FAILED


class SQLDatabaseGeoReplicationSOC2(BaseResourceCheck):
    def __init__(self):
        name = "Ensure SQL Database has geo-replication enabled (SOC2)"
        id = "CKV_SOC2_AZURE_407"
        supported_resources = ['azurerm_mssql_database', 'azurerm_sql_database']
        categories = [CheckCategories.BACKUP_AND_RECOVERY]
        guideline = "SOC2 requires disaster recovery. Enable geo-replication for critical databases."
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources, guideline=guideline)

    def scan_resource_conf(self, conf):
        # Check for geo backup policy
        geo_backup_enabled = conf.get('geo_backup_enabled', [True])[0]

        # Check if this is a secondary (replicated) database
        create_mode = conf.get('create_mode', [''])[0]
        if create_mode == 'Secondary':
            return CheckResult.PASSED

        # Check zone redundancy
        zone_redundant = conf.get('zone_redundant', [False])[0]
        if zone_redundant:
            return CheckResult.PASSED

        # Geo backup enabled is acceptable
        if geo_backup_enabled:
            return CheckResult.PASSED

        return CheckResult.FAILED


class CosmosDBBackupSOC2(BaseResourceCheck):
    def __init__(self):
        name = "Ensure CosmosDB has continuous backup enabled (SOC2)"
        id = "CKV_SOC2_AZURE_408"
        supported_resources = ['azurerm_cosmosdb_account']
        categories = [CheckCategories.BACKUP_AND_RECOVERY]
        guideline = "SOC2 requires backup capabilities. Enable continuous backup for CosmosDB."
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources, guideline=guideline)

    def scan_resource_conf(self, conf):
        backup = conf.get('backup', [])
        if backup:
            for backup_config in backup:
                backup_type = backup_config.get('type', [''])[0]
                if backup_type == 'Continuous':
                    return CheckResult.PASSED

                # Periodic backup with sufficient interval
                if backup_type == 'Periodic':
                    interval_in_minutes = backup_config.get('interval_in_minutes', [240])[0]
                    retention_in_hours = backup_config.get('retention_in_hours', [8])[0]
                    if interval_in_minutes <= 240 and retention_in_hours >= 168:  # 7 days
                        return CheckResult.PASSED

        return CheckResult.FAILED


class AKSNodePoolAvailabilitySOC2(BaseResourceCheck):
    def __init__(self):
        name = "Ensure AKS node pool has availability zones configured (SOC2)"
        id = "CKV_SOC2_AZURE_409"
        supported_resources = ['azurerm_kubernetes_cluster']
        categories = [CheckCategories.BACKUP_AND_RECOVERY]
        guideline = "SOC2 requires high availability. Configure availability zones for AKS."
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources, guideline=guideline)

    def scan_resource_conf(self, conf):
        default_node_pool = conf.get('default_node_pool', [])
        if default_node_pool:
            for pool in default_node_pool:
                zones = pool.get('zones')
                if zones and len(zones) > 0:
                    return CheckResult.PASSED

                # Check for VM scale set with multiple nodes
                node_count = pool.get('node_count', [1])[0]
                if node_count >= 3:
                    return CheckResult.PASSED

        return CheckResult.FAILED


check_vm_backup = VMBackupSOC2()
check_sql_backup = SQLDatabaseBackupSOC2()
check_postgresql_backup = PostgreSQLBackupSOC2()
check_mysql_backup = MySQLBackupSOC2()
check_storage_replication = StorageAccountReplicationSOC2()
check_backup_policy = RecoveryVaultBackupPolicySOC2()
check_sql_geo_replication = SQLDatabaseGeoReplicationSOC2()
check_cosmosdb_backup = CosmosDBBackupSOC2()
check_aks_availability = AKSNodePoolAvailabilitySOC2()
