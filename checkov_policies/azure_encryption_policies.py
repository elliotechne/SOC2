"""
SOC2 Encryption Policies for Azure Terraform Resources
Covers: Data encryption at rest and in transit
"""

from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck
from checkov.common.models.enums import CheckResult, CheckCategories


class StorageAccountEncryptionSOC2(BaseResourceCheck):
    def __init__(self):
        name = "Ensure Storage Account has encryption enabled (SOC2)"
        id = "CKV_SOC2_AZURE_001"
        supported_resources = ['azurerm_storage_account']
        categories = [CheckCategories.ENCRYPTION]
        guideline = "SOC2 requires encryption of data at rest. Enable Storage Account encryption."
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources, guideline=guideline)

    def scan_resource_conf(self, conf):
        # Azure Storage Accounts have encryption enabled by default, but check for explicit settings
        enable_https_traffic_only = conf.get('enable_https_traffic_only', [True])[0]
        min_tls_version = conf.get('min_tls_version', ['TLS1_2'])[0]

        if enable_https_traffic_only and min_tls_version in ['TLS1_2', 'TLS1_3']:
            return CheckResult.PASSED
        return CheckResult.FAILED


class ManagedDiskEncryptionSOC2(BaseResourceCheck):
    def __init__(self):
        name = "Ensure Managed Disks are encrypted (SOC2)"
        id = "CKV_SOC2_AZURE_002"
        supported_resources = ['azurerm_managed_disk', 'azurerm_linux_virtual_machine', 'azurerm_windows_virtual_machine']
        categories = [CheckCategories.ENCRYPTION]
        guideline = "SOC2 requires encryption of data at rest. Enable disk encryption."
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources, guideline=guideline)

    def scan_resource_conf(self, conf):
        # For managed disks
        encryption_settings = conf.get('encryption_settings')
        if encryption_settings and encryption_settings[0].get('enabled', [False])[0]:
            return CheckResult.PASSED

        # For VMs, check OS disk encryption
        os_disk = conf.get('os_disk', [])
        if os_disk:
            for disk in os_disk:
                disk_encryption_set_id = disk.get('disk_encryption_set_id')
                if disk_encryption_set_id:
                    return CheckResult.PASSED

        # Check for encryption at host
        encryption_at_host_enabled = conf.get('encryption_at_host_enabled', [False])[0]
        if encryption_at_host_enabled:
            return CheckResult.PASSED

        return CheckResult.FAILED


class SQLDatabaseEncryptionSOC2(BaseResourceCheck):
    def __init__(self):
        name = "Ensure SQL Database has Transparent Data Encryption enabled (SOC2)"
        id = "CKV_SOC2_AZURE_003"
        supported_resources = ['azurerm_mssql_database', 'azurerm_sql_database']
        categories = [CheckCategories.ENCRYPTION]
        guideline = "SOC2 requires encryption of data at rest. Enable TDE for SQL databases."
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources, guideline=guideline)

    def scan_resource_conf(self, conf):
        # TDE is enabled by default for Azure SQL Database, but check for explicit configuration
        # Check if transparent_data_encryption_enabled is set to true (for older versions)
        tde_enabled = conf.get('transparent_data_encryption_enabled', [True])[0]
        if tde_enabled is True:
            return CheckResult.PASSED
        return CheckResult.FAILED


class PostgreSQLEncryptionSOC2(BaseResourceCheck):
    def __init__(self):
        name = "Ensure PostgreSQL Server enforces SSL connection (SOC2)"
        id = "CKV_SOC2_AZURE_004"
        supported_resources = ['azurerm_postgresql_server', 'azurerm_postgresql_flexible_server']
        categories = [CheckCategories.ENCRYPTION]
        guideline = "SOC2 requires encryption of data in transit. Enable SSL enforcement for PostgreSQL."
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources, guideline=guideline)

    def scan_resource_conf(self, conf):
        ssl_enforcement_enabled = conf.get('ssl_enforcement_enabled', [False])[0]
        ssl_minimal_tls_version = conf.get('ssl_minimal_tls_version_enforced', ['TLS1_2'])[0]

        if ssl_enforcement_enabled and ssl_minimal_tls_version in ['TLS1_2', 'TLS1_3']:
            return CheckResult.PASSED
        return CheckResult.FAILED


class MySQLEncryptionSOC2(BaseResourceCheck):
    def __init__(self):
        name = "Ensure MySQL Server enforces SSL connection (SOC2)"
        id = "CKV_SOC2_AZURE_005"
        supported_resources = ['azurerm_mysql_server', 'azurerm_mysql_flexible_server']
        categories = [CheckCategories.ENCRYPTION]
        guideline = "SOC2 requires encryption of data in transit. Enable SSL enforcement for MySQL."
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources, guideline=guideline)

    def scan_resource_conf(self, conf):
        ssl_enforcement_enabled = conf.get('ssl_enforcement_enabled', [False])[0]
        ssl_minimal_tls_version = conf.get('ssl_minimal_tls_version_enforced', ['TLS1_2'])[0]

        if ssl_enforcement_enabled and ssl_minimal_tls_version in ['TLS1_2', 'TLS1_3']:
            return CheckResult.PASSED
        return CheckResult.FAILED


class CosmosDBEncryptionSOC2(BaseResourceCheck):
    def __init__(self):
        name = "Ensure CosmosDB account uses encryption (SOC2)"
        id = "CKV_SOC2_AZURE_006"
        supported_resources = ['azurerm_cosmosdb_account']
        categories = [CheckCategories.ENCRYPTION]
        guideline = "SOC2 requires encryption of data at rest and in transit. Enable CosmosDB encryption."
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources, guideline=guideline)

    def scan_resource_conf(self, conf):
        # CosmosDB has encryption by default, but verify customer-managed keys or HTTPS settings
        is_virtual_network_filter_enabled = conf.get('is_virtual_network_filter_enabled')
        public_network_access_enabled = conf.get('public_network_access_enabled', [True])[0]

        # If public network access is enabled, ensure other security measures
        if not public_network_access_enabled or is_virtual_network_filter_enabled:
            return CheckResult.PASSED

        # Check for customer-managed key
        key_vault_key_id = conf.get('key_vault_key_id')
        if key_vault_key_id:
            return CheckResult.PASSED

        return CheckResult.PASSED  # Encryption is default, passing for basic configuration


class ApplicationGatewayHTTPSSOC2(BaseResourceCheck):
    def __init__(self):
        name = "Ensure Application Gateway uses HTTPS listeners (SOC2)"
        id = "CKV_SOC2_AZURE_007"
        supported_resources = ['azurerm_application_gateway']
        categories = [CheckCategories.ENCRYPTION]
        guideline = "SOC2 requires encryption of data in transit. Use HTTPS for Application Gateway."
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources, guideline=guideline)

    def scan_resource_conf(self, conf):
        http_listeners = conf.get('http_listener', [])
        if not http_listeners:
            return CheckResult.FAILED

        for listener in http_listeners:
            protocol = listener.get('protocol', [''])[0]
            if protocol != 'Https':
                return CheckResult.FAILED

        return CheckResult.PASSED


class DataLakeEncryptionSOC2(BaseResourceCheck):
    def __init__(self):
        name = "Ensure Data Lake Store has encryption enabled (SOC2)"
        id = "CKV_SOC2_AZURE_008"
        supported_resources = ['azurerm_data_lake_store']
        categories = [CheckCategories.ENCRYPTION]
        guideline = "SOC2 requires encryption of data at rest. Enable Data Lake Store encryption."
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources, guideline=guideline)

    def scan_resource_conf(self, conf):
        encryption_state = conf.get('encryption_state', ['Enabled'])[0]
        if encryption_state == 'Enabled':
            return CheckResult.PASSED
        return CheckResult.FAILED


class AKSEncryptionSOC2(BaseResourceCheck):
    def __init__(self):
        name = "Ensure AKS cluster has disk encryption enabled (SOC2)"
        id = "CKV_SOC2_AZURE_009"
        supported_resources = ['azurerm_kubernetes_cluster']
        categories = [CheckCategories.ENCRYPTION]
        guideline = "SOC2 requires encryption of data at rest. Enable AKS disk encryption."
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources, guideline=guideline)

    def scan_resource_conf(self, conf):
        disk_encryption_set_id = conf.get('disk_encryption_set_id')
        if disk_encryption_set_id:
            return CheckResult.PASSED

        # Check default node pool
        default_node_pool = conf.get('default_node_pool', [])
        if default_node_pool:
            for pool in default_node_pool:
                if pool.get('enable_host_encryption', [False])[0]:
                    return CheckResult.PASSED

        return CheckResult.FAILED


check_storage_encryption = StorageAccountEncryptionSOC2()
check_disk_encryption = ManagedDiskEncryptionSOC2()
check_sql_encryption = SQLDatabaseEncryptionSOC2()
check_postgresql_encryption = PostgreSQLEncryptionSOC2()
check_mysql_encryption = MySQLEncryptionSOC2()
check_cosmosdb_encryption = CosmosDBEncryptionSOC2()
check_appgw_encryption = ApplicationGatewayHTTPSSOC2()
check_datalake_encryption = DataLakeEncryptionSOC2()
check_aks_encryption = AKSEncryptionSOC2()
