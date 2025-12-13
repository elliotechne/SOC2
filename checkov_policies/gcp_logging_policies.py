"""
SOC2 Logging and Monitoring Policies for GCP Terraform Resources
Covers: Cloud Logging, Cloud Monitoring, Audit Logs
"""

from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck
from checkov.common.models.enums import CheckResult, CheckCategories


class GCPProjectLoggingSOC2(BaseResourceCheck):
    def __init__(self):
        name = "Ensure project has logging enabled (SOC2)"
        id = "CKV_SOC2_GCP_201"
        supported_resources = ['google_logging_project_sink']
        categories = [CheckCategories.LOGGING]
        guideline = "SOC2 requires audit logging. Enable Cloud Logging for projects."
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources, guideline=guideline)

    def scan_resource_conf(self, conf):
        destination = conf.get('destination')
        if destination:
            return CheckResult.PASSED
        return CheckResult.FAILED


class GCPStorageBucketLoggingSOC2(BaseResourceCheck):
    def __init__(self):
        name = "Ensure GCS buckets have access logging enabled (SOC2)"
        id = "CKV_SOC2_GCP_202"
        supported_resources = ['google_storage_bucket']
        categories = [CheckCategories.LOGGING]
        guideline = "SOC2 requires access logging. Enable logging for GCS buckets."
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources, guideline=guideline)

    def scan_resource_conf(self, conf):
        logging = conf.get('logging')
        if logging and logging[0].get('log_bucket'):
            return CheckResult.PASSED
        return CheckResult.FAILED


class GCPSQLAuditLoggingSOC2(BaseResourceCheck):
    def __init__(self):
        name = "Ensure Cloud SQL has audit logging enabled (SOC2)"
        id = "CKV_SOC2_GCP_203"
        supported_resources = ['google_sql_database_instance']
        categories = [CheckCategories.LOGGING]
        guideline = "SOC2 requires database audit logging. Enable Cloud SQL audit logs."
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources, guideline=guideline)

    def scan_resource_conf(self, conf):
        settings = conf.get('settings', [])
        if settings:
            for setting in settings:
                database_flags = setting.get('database_flags', [])
                for flag in database_flags:
                    if flag.get('name', [''])[0] == 'log_statement':
                        return CheckResult.PASSED
        return CheckResult.FAILED


class GCPComputeFlowLogsSOC2(BaseResourceCheck):
    def __init__(self):
        name = "Ensure VPC subnets have flow logs enabled (SOC2)"
        id = "CKV_SOC2_GCP_204"
        supported_resources = ['google_compute_subnetwork']
        categories = [CheckCategories.LOGGING]
        guideline = "SOC2 requires network traffic logging. Enable VPC flow logs."
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources, guideline=guideline)

    def scan_resource_conf(self, conf):
        log_config = conf.get('log_config')
        if log_config:
            return CheckResult.PASSED
        return CheckResult.FAILED


class GCPLoadBalancerLoggingSOC2(BaseResourceCheck):
    def __init__(self):
        name = "Ensure load balancers have logging enabled (SOC2)"
        id = "CKV_SOC2_GCP_205"
        supported_resources = ['google_compute_backend_service']
        categories = [CheckCategories.LOGGING]
        guideline = "SOC2 requires access logging. Enable load balancer logging."
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources, guideline=guideline)

    def scan_resource_conf(self, conf):
        log_config = conf.get('log_config')
        if log_config and log_config[0].get('enable', [False])[0]:
            return CheckResult.PASSED
        return CheckResult.FAILED


class GCPAuditLogRetentionSOC2(BaseResourceCheck):
    def __init__(self):
        name = "Ensure audit logs have retention policy (SOC2)"
        id = "CKV_SOC2_GCP_206"
        supported_resources = ['google_logging_project_bucket_config']
        categories = [CheckCategories.LOGGING]
        guideline = "SOC2 requires log retention. Configure retention for audit logs."
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources, guideline=guideline)

    def scan_resource_conf(self, conf):
        retention_days = conf.get('retention_days', [0])[0]
        if retention_days >= 90:
            return CheckResult.PASSED
        return CheckResult.FAILED


check_gcp_project_logging = GCPProjectLoggingSOC2()
check_gcp_storage_logging = GCPStorageBucketLoggingSOC2()
check_gcp_sql_logging = GCPSQLAuditLoggingSOC2()
check_gcp_flow_logs = GCPComputeFlowLogsSOC2()
check_gcp_lb_logging = GCPLoadBalancerLoggingSOC2()
check_gcp_log_retention = GCPAuditLogRetentionSOC2()
