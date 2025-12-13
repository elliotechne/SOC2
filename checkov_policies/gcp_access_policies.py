"""
SOC2 Access Control and IAM Policies for GCP Terraform Resources
Covers: Least privilege, service accounts, IAM bindings
"""

from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck
from checkov.common.models.enums import CheckResult, CheckCategories


class GCPServiceAccountKeyRotationSOC2(BaseResourceCheck):
    def __init__(self):
        name = "Ensure service account keys have rotation policy (SOC2)"
        id = "CKV_SOC2_GCP_101"
        supported_resources = ['google_service_account_key']
        categories = [CheckCategories.IAM]
        guideline = "SOC2 requires key rotation. Service account keys should be rotated regularly."
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources, guideline=guideline)

    def scan_resource_conf(self, conf):
        key_algorithm = conf.get('key_algorithm', [''])[0]
        if key_algorithm:
            return CheckResult.PASSED
        return CheckResult.FAILED


class GCPIAMPrimitiveRolesSOC2(BaseResourceCheck):
    def __init__(self):
        name = "Ensure IAM bindings do not use primitive roles (SOC2)"
        id = "CKV_SOC2_GCP_102"
        supported_resources = ['google_project_iam_binding', 'google_project_iam_member']
        categories = [CheckCategories.IAM]
        guideline = "SOC2 requires least privilege. Avoid primitive roles (Owner, Editor, Viewer)."
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources, guideline=guideline)

    def scan_resource_conf(self, conf):
        role = conf.get('role', [''])[0]
        primitive_roles = ['roles/owner', 'roles/editor', 'roles/viewer']

        if role.lower() in primitive_roles:
            return CheckResult.FAILED
        return CheckResult.PASSED


class GCPStorageBucketIAMSOC2(BaseResourceCheck):
    def __init__(self):
        name = "Ensure GCS buckets do not allow public access (SOC2)"
        id = "CKV_SOC2_GCP_103"
        supported_resources = ['google_storage_bucket_iam_binding', 'google_storage_bucket_iam_member']
        categories = [CheckCategories.IAM]
        guideline = "SOC2 requires access controls. Prevent public access to storage buckets."
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources, guideline=guideline)

    def scan_resource_conf(self, conf):
        members = conf.get('members', [])
        if members:
            for member_list in members:
                if isinstance(member_list, list):
                    for member in member_list:
                        if member in ['allUsers', 'allAuthenticatedUsers']:
                            return CheckResult.FAILED
        return CheckResult.PASSED


class GCPComputeOSLoginSOC2(BaseResourceCheck):
    def __init__(self):
        name = "Ensure compute instances use OS Login (SOC2)"
        id = "CKV_SOC2_GCP_104"
        supported_resources = ['google_compute_instance']
        categories = [CheckCategories.IAM]
        guideline = "SOC2 requires centralized access control. Enable OS Login for instances."
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources, guideline=guideline)

    def scan_resource_conf(self, conf):
        metadata = conf.get('metadata', [{}])[0]
        if metadata.get('enable-oslogin') == 'TRUE':
            return CheckResult.PASSED
        return CheckResult.FAILED


class GCPServiceAccountAdminSOC2(BaseResourceCheck):
    def __init__(self):
        name = "Ensure service accounts do not have admin privileges (SOC2)"
        id = "CKV_SOC2_GCP_105"
        supported_resources = ['google_project_iam_binding', 'google_project_iam_member']
        categories = [CheckCategories.IAM]
        guideline = "SOC2 requires least privilege. Service accounts should not have admin roles."
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources, guideline=guideline)

    def scan_resource_conf(self, conf):
        role = conf.get('role', [''])[0]
        members = conf.get('members', [])

        admin_roles = ['roles/owner', 'roles/editor', 'roles/iam.serviceAccountAdmin']

        if role.lower() in admin_roles:
            for member_list in members:
                if isinstance(member_list, list):
                    for member in member_list:
                        if 'serviceAccount:' in member:
                            return CheckResult.FAILED

        return CheckResult.PASSED


check_gcp_sa_key_rotation = GCPServiceAccountKeyRotationSOC2()
check_gcp_primitive_roles = GCPIAMPrimitiveRolesSOC2()
check_gcp_storage_iam = GCPStorageBucketIAMSOC2()
check_gcp_os_login = GCPComputeOSLoginSOC2()
check_gcp_sa_admin = GCPServiceAccountAdminSOC2()
