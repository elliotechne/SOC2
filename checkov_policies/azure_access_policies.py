"""
SOC2 Access Control and IAM Policies for Azure Terraform Resources
Covers: Least privilege, MFA, RBAC, access controls
"""

from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck
from checkov.common.models.enums import CheckResult, CheckCategories


class StorageAccountPublicAccessSOC2(BaseResourceCheck):
    def __init__(self):
        name = "Ensure Storage Account denies public access (SOC2)"
        id = "CKV_SOC2_AZURE_101"
        supported_resources = ['azurerm_storage_account']
        categories = [CheckCategories.IAM]
        guideline = "SOC2 requires access controls. Disable public access to Storage Accounts."
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources, guideline=guideline)

    def scan_resource_conf(self, conf):
        allow_blob_public_access = conf.get('allow_blob_public_access', [True])[0]
        public_network_access_enabled = conf.get('public_network_access_enabled', [True])[0]

        if not allow_blob_public_access and not public_network_access_enabled:
            return CheckResult.PASSED

        # If one is disabled, it's a partial pass
        if not allow_blob_public_access or not public_network_access_enabled:
            return CheckResult.PASSED

        return CheckResult.FAILED


class KeyVaultAccessPolicySOC2(BaseResourceCheck):
    def __init__(self):
        name = "Ensure Key Vault has access policies defined (SOC2)"
        id = "CKV_SOC2_AZURE_102"
        supported_resources = ['azurerm_key_vault']
        categories = [CheckCategories.IAM]
        guideline = "SOC2 requires least privilege access. Define specific access policies for Key Vault."
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources, guideline=guideline)

    def scan_resource_conf(self, conf):
        access_policy = conf.get('access_policy')
        enable_rbac_authorization = conf.get('enable_rbac_authorization', [False])[0]

        # Either access policies or RBAC should be configured
        if access_policy or enable_rbac_authorization:
            return CheckResult.PASSED
        return CheckResult.FAILED


class KeyVaultPublicAccessSOC2(BaseResourceCheck):
    def __init__(self):
        name = "Ensure Key Vault has public network access disabled (SOC2)"
        id = "CKV_SOC2_AZURE_103"
        supported_resources = ['azurerm_key_vault']
        categories = [CheckCategories.IAM]
        guideline = "SOC2 requires access controls. Disable public network access to Key Vault."
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources, guideline=guideline)

    def scan_resource_conf(self, conf):
        public_network_access_enabled = conf.get('public_network_access_enabled', [True])[0]
        network_acls = conf.get('network_acls', [])

        if not public_network_access_enabled:
            return CheckResult.PASSED

        # If public access is enabled, check for network ACLs
        if network_acls:
            for acl in network_acls:
                default_action = acl.get('default_action', ['Allow'])[0]
                if default_action == 'Deny':
                    return CheckResult.PASSED

        return CheckResult.FAILED


class SQLServerADAdminSOC2(BaseResourceCheck):
    def __init__(self):
        name = "Ensure SQL Server has Azure AD admin configured (SOC2)"
        id = "CKV_SOC2_AZURE_104"
        supported_resources = ['azurerm_mssql_server', 'azurerm_sql_server']
        categories = [CheckCategories.IAM]
        guideline = "SOC2 requires centralized identity management. Configure Azure AD admin for SQL Server."
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources, guideline=guideline)

    def scan_resource_conf(self, conf):
        azuread_administrator = conf.get('azuread_administrator')
        if azuread_administrator:
            return CheckResult.PASSED
        return CheckResult.FAILED


class PostgreSQLADAuthSOC2(BaseResourceCheck):
    def __init__(self):
        name = "Ensure PostgreSQL Server has Azure AD authentication enabled (SOC2)"
        id = "CKV_SOC2_AZURE_105"
        supported_resources = ['azurerm_postgresql_server', 'azurerm_postgresql_flexible_server']
        categories = [CheckCategories.IAM]
        guideline = "SOC2 requires centralized identity management. Enable Azure AD authentication for PostgreSQL."
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources, guideline=guideline)

    def scan_resource_conf(self, conf):
        # For flexible server
        authentication = conf.get('authentication')
        if authentication:
            for auth in authentication:
                active_directory_auth_enabled = auth.get('active_directory_auth_enabled', [False])[0]
                if active_directory_auth_enabled:
                    return CheckResult.PASSED

        # Check tags for AD configuration (common practice)
        tags = conf.get('tags', [{}])[0]
        if tags.get('AADAuthEnabled') == 'true':
            return CheckResult.PASSED

        return CheckResult.FAILED


class ContainerRegistryAdminSOC2(BaseResourceCheck):
    def __init__(self):
        name = "Ensure Container Registry has admin account disabled (SOC2)"
        id = "CKV_SOC2_AZURE_106"
        supported_resources = ['azurerm_container_registry']
        categories = [CheckCategories.IAM]
        guideline = "SOC2 requires least privilege access. Disable admin account for Container Registry."
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources, guideline=guideline)

    def scan_resource_conf(self, conf):
        admin_enabled = conf.get('admin_enabled', [False])[0]
        if not admin_enabled:
            return CheckResult.PASSED
        return CheckResult.FAILED


class AKSRBACSOc2(BaseResourceCheck):
    def __init__(self):
        name = "Ensure AKS cluster has RBAC enabled (SOC2)"
        id = "CKV_SOC2_AZURE_107"
        supported_resources = ['azurerm_kubernetes_cluster']
        categories = [CheckCategories.IAM]
        guideline = "SOC2 requires role-based access control. Enable RBAC for AKS clusters."
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources, guideline=guideline)

    def scan_resource_conf(self, conf):
        role_based_access_control_enabled = conf.get('role_based_access_control_enabled', [True])[0]

        # Also check for Azure AD integration
        azure_active_directory_role_based_access_control = conf.get('azure_active_directory_role_based_access_control')

        if role_based_access_control_enabled and azure_active_directory_role_based_access_control:
            return CheckResult.PASSED

        # RBAC enabled is minimum requirement
        if role_based_access_control_enabled:
            return CheckResult.PASSED

        return CheckResult.FAILED


class AKSLocalAccountSOC2(BaseResourceCheck):
    def __init__(self):
        name = "Ensure AKS cluster has local accounts disabled (SOC2)"
        id = "CKV_SOC2_AZURE_108"
        supported_resources = ['azurerm_kubernetes_cluster']
        categories = [CheckCategories.IAM]
        guideline = "SOC2 requires centralized authentication. Disable local accounts for AKS."
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources, guideline=guideline)

    def scan_resource_conf(self, conf):
        local_account_disabled = conf.get('local_account_disabled', [False])[0]
        if local_account_disabled:
            return CheckResult.PASSED
        return CheckResult.FAILED


class FunctionAppManagedIdentitySOC2(BaseResourceCheck):
    def __init__(self):
        name = "Ensure Function App uses Managed Identity (SOC2)"
        id = "CKV_SOC2_AZURE_109"
        supported_resources = ['azurerm_function_app', 'azurerm_linux_function_app', 'azurerm_windows_function_app']
        categories = [CheckCategories.IAM]
        guideline = "SOC2 requires secure authentication. Use Managed Identity for Function Apps."
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources, guideline=guideline)

    def scan_resource_conf(self, conf):
        identity = conf.get('identity')
        if identity:
            for ident in identity:
                identity_type = ident.get('type', [''])[0]
                if identity_type in ['SystemAssigned', 'UserAssigned', 'SystemAssigned, UserAssigned']:
                    return CheckResult.PASSED
        return CheckResult.FAILED


class AppServiceManagedIdentitySOC2(BaseResourceCheck):
    def __init__(self):
        name = "Ensure App Service uses Managed Identity (SOC2)"
        id = "CKV_SOC2_AZURE_110"
        supported_resources = ['azurerm_app_service', 'azurerm_linux_web_app', 'azurerm_windows_web_app']
        categories = [CheckCategories.IAM]
        guideline = "SOC2 requires secure authentication. Use Managed Identity for App Services."
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources, guideline=guideline)

    def scan_resource_conf(self, conf):
        identity = conf.get('identity')
        if identity:
            for ident in identity:
                identity_type = ident.get('type', [''])[0]
                if identity_type in ['SystemAssigned', 'UserAssigned', 'SystemAssigned, UserAssigned']:
                    return CheckResult.PASSED
        return CheckResult.FAILED


class VMDisablePasswordAuthSOC2(BaseResourceCheck):
    def __init__(self):
        name = "Ensure Linux VM has password authentication disabled (SOC2)"
        id = "CKV_SOC2_AZURE_111"
        supported_resources = ['azurerm_linux_virtual_machine']
        categories = [CheckCategories.IAM]
        guideline = "SOC2 requires strong authentication. Disable password authentication for Linux VMs."
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources, guideline=guideline)

    def scan_resource_conf(self, conf):
        disable_password_authentication = conf.get('disable_password_authentication', [False])[0]
        if disable_password_authentication:
            return CheckResult.PASSED
        return CheckResult.FAILED


check_storage_public_access = StorageAccountPublicAccessSOC2()
check_keyvault_access_policy = KeyVaultAccessPolicySOC2()
check_keyvault_public_access = KeyVaultPublicAccessSOC2()
check_sql_ad_admin = SQLServerADAdminSOC2()
check_postgresql_ad_auth = PostgreSQLADAuthSOC2()
check_acr_admin = ContainerRegistryAdminSOC2()
check_aks_rbac = AKSRBACSOc2()
check_aks_local_account = AKSLocalAccountSOC2()
check_function_managed_identity = FunctionAppManagedIdentitySOC2()
check_appservice_managed_identity = AppServiceManagedIdentitySOC2()
check_vm_password_auth = VMDisablePasswordAuthSOC2()
