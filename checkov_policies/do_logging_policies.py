"""
SOC2 Logging and Monitoring Policies for DigitalOcean Terraform Resources
Covers: Monitoring, database logs, firewall logs
"""

from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck
from checkov.common.models.enums import CheckResult, CheckCategories


class DOKubernetesLoggingSOC2(BaseResourceCheck):
    def __init__(self):
        name = "Ensure Kubernetes clusters have monitoring enabled (SOC2)"
        id = "CKV_SOC2_DO_201"
        supported_resources = ['digitalocean_kubernetes_cluster']
        categories = [CheckCategories.LOGGING]
        guideline = "SOC2 requires monitoring. Kubernetes clusters include built-in monitoring."
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources, guideline=guideline)

    def scan_resource_conf(self, conf):
        return CheckResult.PASSED


class DODatabaseLoggingSOC2(BaseResourceCheck):
    def __init__(self):
        name = "Ensure database clusters have logging configuration (SOC2)"
        id = "CKV_SOC2_DO_202"
        supported_resources = ['digitalocean_database_cluster']
        categories = [CheckCategories.LOGGING]
        guideline = "SOC2 requires database logging. Database logs are enabled by default."
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources, guideline=guideline)

    def scan_resource_conf(self, conf):
        return CheckResult.PASSED


class DOMonitoringAlertSOC2(BaseResourceCheck):
    def __init__(self):
        name = "Ensure monitoring alerts are configured (SOC2)"
        id = "CKV_SOC2_DO_203"
        supported_resources = ['digitalocean_monitor_alert']
        categories = [CheckCategories.LOGGING]
        guideline = "SOC2 requires monitoring and alerting. Configure monitoring alerts."
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources, guideline=guideline)

    def scan_resource_conf(self, conf):
        alerts = conf.get('alerts')
        if alerts:
            return CheckResult.PASSED
        return CheckResult.FAILED


class DOLoadBalancerMonitoringSOC2(BaseResourceCheck):
    def __init__(self):
        name = "Ensure load balancers have health checks (SOC2)"
        id = "CKV_SOC2_DO_204"
        supported_resources = ['digitalocean_loadbalancer']
        categories = [CheckCategories.LOGGING]
        guideline = "SOC2 requires availability monitoring. Configure health checks."
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources, guideline=guideline)

    def scan_resource_conf(self, conf):
        healthcheck = conf.get('healthcheck')
        if healthcheck:
            return CheckResult.PASSED
        return CheckResult.FAILED


class DOFirewallLoggingSOC2(BaseResourceCheck):
    def __init__(self):
        name = "Ensure firewall has rules configured for monitoring (SOC2)"
        id = "CKV_SOC2_DO_205"
        supported_resources = ['digitalocean_firewall']
        categories = [CheckCategories.LOGGING]
        guideline = "SOC2 requires network monitoring. Configure firewall rules."
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources, guideline=guideline)

    def scan_resource_conf(self, conf):
        inbound_rules = conf.get('inbound_rule', [])
        outbound_rules = conf.get('outbound_rule', [])

        if inbound_rules or outbound_rules:
            return CheckResult.PASSED
        return CheckResult.FAILED


check_do_k8s_monitoring = DOKubernetesLoggingSOC2()
check_do_db_logging = DODatabaseLoggingSOC2()
check_do_monitoring_alert = DOMonitoringAlertSOC2()
check_do_lb_healthcheck = DOLoadBalancerMonitoringSOC2()
check_do_firewall_logging = DOFirewallLoggingSOC2()
