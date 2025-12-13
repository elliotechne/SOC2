"""
SOC2 Network Security Policies for DigitalOcean Terraform Resources
Covers: Firewall rules, network isolation, security configuration
"""

from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck
from checkov.common.models.enums import CheckResult, CheckCategories


class DOFirewallRestrictedIngressSOC2(BaseResourceCheck):
    def __init__(self):
        name = "Ensure firewall rules restrict ingress appropriately (SOC2)"
        id = "CKV_SOC2_DO_301"
        supported_resources = ['digitalocean_firewall']
        categories = [CheckCategories.NETWORKING]
        guideline = "SOC2 requires network segmentation. Configure restrictive firewall rules."
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources, guideline=guideline)

    def scan_resource_conf(self, conf, entity_type):
        inbound_rules = conf.get('inbound_rule', [])

        for rule in inbound_rules:
            source_addresses = rule.get('source_addresses', [])
            for addr_list in source_addresses:
                if '0.0.0.0/0' in addr_list or '::/0' in addr_list:
                    return CheckResult.FAILED

        return CheckResult.PASSED


class DOFirewallNoSSHFromInternetSOC2(BaseResourceCheck):
    def __init__(self):
        name = "Ensure SSH (port 22) is not open to the internet (SOC2)"
        id = "CKV_SOC2_DO_302"
        supported_resources = ['digitalocean_firewall']
        categories = [CheckCategories.NETWORKING]
        guideline = "SOC2 requires secure access. Do not expose SSH to the internet."
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources, guideline=guideline)

    def scan_resource_conf(self, conf, entity_type):
        inbound_rules = conf.get('inbound_rule', [])

        for rule in inbound_rules:
            protocol = rule.get('protocol', [''])[0]
            port_range = rule.get('port_range', [''])[0]
            source_addresses = rule.get('source_addresses', [])

            if protocol == 'tcp' and ('22' in port_range or port_range == '22'):
                for addr_list in source_addresses:
                    if '0.0.0.0/0' in addr_list:
                        return CheckResult.FAILED

        return CheckResult.PASSED


class DODatabasePrivateNetworkSOC2(BaseResourceCheck):
    def __init__(self):
        name = "Ensure database clusters use private networking (SOC2)"
        id = "CKV_SOC2_DO_303"
        supported_resources = ['digitalocean_database_cluster']
        categories = [CheckCategories.NETWORKING]
        guideline = "SOC2 requires network isolation. Use private networking for databases."
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources, guideline=guideline)

    def scan_resource_conf(self, conf, entity_type):
        private_network_uuid = conf.get('private_network_uuid')
        if private_network_uuid:
            return CheckResult.PASSED
        return CheckResult.FAILED


class DOKubernetesPrivateClusterSOC2(BaseResourceCheck):
    def __init__(self):
        name = "Ensure Kubernetes clusters use private networking (SOC2)"
        id = "CKV_SOC2_DO_304"
        supported_resources = ['digitalocean_kubernetes_cluster']
        categories = [CheckCategories.NETWORKING]
        guideline = "SOC2 requires network isolation. Use VPC for Kubernetes clusters."
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources, guideline=guideline)

    def scan_resource_conf(self, conf, entity_type):
        vpc_uuid = conf.get('vpc_uuid')
        if vpc_uuid:
            return CheckResult.PASSED
        return CheckResult.FAILED


class DODropletPrivateNetworkingSOC2(BaseResourceCheck):
    def __init__(self):
        name = "Ensure droplets use private networking (SOC2)"
        id = "CKV_SOC2_DO_305"
        supported_resources = ['digitalocean_droplet']
        categories = [CheckCategories.NETWORKING]
        guideline = "SOC2 requires network isolation. Enable private networking for droplets."
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources, guideline=guideline)

    def scan_resource_conf(self, conf, entity_type):
        private_networking = conf.get('private_networking', [False])[0]
        vpc_uuid = conf.get('vpc_uuid')

        if private_networking or vpc_uuid:
            return CheckResult.PASSED
        return CheckResult.FAILED


class DOVPCConfiguredSOC2(BaseResourceCheck):
    def __init__(self):
        name = "Ensure VPC is properly configured (SOC2)"
        id = "CKV_SOC2_DO_306"
        supported_resources = ['digitalocean_vpc']
        categories = [CheckCategories.NETWORKING]
        guideline = "SOC2 requires network segmentation. Configure VPC appropriately."
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources, guideline=guideline)

    def scan_resource_conf(self, conf, entity_type):
        ip_range = conf.get('ip_range')
        if ip_range:
            return CheckResult.PASSED
        return CheckResult.FAILED


check_do_fw_restricted = DOFirewallRestrictedIngressSOC2()
check_do_fw_no_ssh = DOFirewallNoSSHFromInternetSOC2()
check_do_db_private = DODatabasePrivateNetworkSOC2()
check_do_k8s_private = DOKubernetesPrivateClusterSOC2()
check_do_droplet_private = DODropletPrivateNetworkingSOC2()
check_do_vpc_configured = DOVPCConfiguredSOC2()
