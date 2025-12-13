"""
SOC2 Encryption Policies for GCP Terraform Resources
Covers: Data encryption at rest and in transit
"""

from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck
from checkov.common.models.enums import CheckResult, CheckCategories


class GCPStorageBucketEncryptionSOC2(BaseResourceCheck):
    def __init__(self):
        name = "Ensure GCS buckets use customer-managed encryption keys (SOC2)"
        id = "CKV_SOC2_GCP_001"
        supported_resources = ['google_storage_bucket']
        categories = [CheckCategories.ENCRYPTION]
        guideline = "SOC2 requires encryption of data at rest. Use CMEK for GCS buckets."
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources, guideline=guideline)

    def scan_resource_conf(self, conf, entity_type):
        encryption = conf.get('encryption')
        if encryption and encryption[0].get('default_kms_key_name'):
            return CheckResult.PASSED
        return CheckResult.FAILED


class GCPComputeDiskEncryptionSOC2(BaseResourceCheck):
    def __init__(self):
        name = "Ensure GCP compute disks are encrypted with CMEK (SOC2)"
        id = "CKV_SOC2_GCP_002"
        supported_resources = ['google_compute_disk', 'google_compute_instance']
        categories = [CheckCategories.ENCRYPTION]
        guideline = "SOC2 requires encryption of data at rest. Use CMEK for compute disks."
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources, guideline=guideline)

    def scan_resource_conf(self, conf, entity_type):
        if entity_type == 'google_compute_disk':
            if conf.get('disk_encryption_key'):
                return CheckResult.PASSED

        if entity_type == 'google_compute_instance':
            boot_disk = conf.get('boot_disk', [])
            if boot_disk:
                for disk in boot_disk:
                    if disk.get('disk_encryption_key_raw') or disk.get('kms_key_self_link'):
                        return CheckResult.PASSED

        return CheckResult.FAILED


class GCPSQLEncryptionSOC2(BaseResourceCheck):
    def __init__(self):
        name = "Ensure Cloud SQL instances are encrypted with CMEK (SOC2)"
        id = "CKV_SOC2_GCP_003"
        supported_resources = ['google_sql_database_instance']
        categories = [CheckCategories.ENCRYPTION]
        guideline = "SOC2 requires encryption of data at rest. Use CMEK for Cloud SQL."
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources, guideline=guideline)

    def scan_resource_conf(self, conf, entity_type):
        encryption = conf.get('encryption_key_name')
        if encryption:
            return CheckResult.PASSED
        return CheckResult.FAILED


class GCPBigQueryEncryptionSOC2(BaseResourceCheck):
    def __init__(self):
        name = "Ensure BigQuery datasets are encrypted with CMEK (SOC2)"
        id = "CKV_SOC2_GCP_004"
        supported_resources = ['google_bigquery_dataset', 'google_bigquery_table']
        categories = [CheckCategories.ENCRYPTION]
        guideline = "SOC2 requires encryption of data at rest. Use CMEK for BigQuery."
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources, guideline=guideline)

    def scan_resource_conf(self, conf, entity_type):
        encryption_config = conf.get('encryption_configuration')
        if encryption_config and encryption_config[0].get('kms_key_name'):
            return CheckResult.PASSED
        return CheckResult.FAILED


class GCPLoadBalancerHTTPSSOC2(BaseResourceCheck):
    def __init__(self):
        name = "Ensure GCP load balancers use HTTPS (SOC2)"
        id = "CKV_SOC2_GCP_005"
        supported_resources = ['google_compute_target_https_proxy', 'google_compute_url_map']
        categories = [CheckCategories.ENCRYPTION]
        guideline = "SOC2 requires encryption of data in transit. Use HTTPS for load balancers."
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources, guideline=guideline)

    def scan_resource_conf(self, conf, entity_type):
        if entity_type == 'google_compute_target_https_proxy':
            return CheckResult.PASSED
        return CheckResult.FAILED


class GCPPubSubEncryptionSOC2(BaseResourceCheck):
    def __init__(self):
        name = "Ensure Pub/Sub topics are encrypted with CMEK (SOC2)"
        id = "CKV_SOC2_GCP_006"
        supported_resources = ['google_pubsub_topic']
        categories = [CheckCategories.ENCRYPTION]
        guideline = "SOC2 requires encryption of data at rest. Use CMEK for Pub/Sub."
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources, guideline=guideline)

    def scan_resource_conf(self, conf, entity_type):
        kms_key_name = conf.get('kms_key_name')
        if kms_key_name:
            return CheckResult.PASSED
        return CheckResult.FAILED


check_gcs_encryption = GCPStorageBucketEncryptionSOC2()
check_gcp_disk_encryption = GCPComputeDiskEncryptionSOC2()
check_gcp_sql_encryption = GCPSQLEncryptionSOC2()
check_bigquery_encryption = GCPBigQueryEncryptionSOC2()
check_gcp_lb_https = GCPLoadBalancerHTTPSSOC2()
check_pubsub_encryption = GCPPubSubEncryptionSOC2()
