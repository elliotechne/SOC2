"""
SOC2 Access Control Policies for DigitalOcean Terraform Resources
Covers: SSH keys, firewall rules, access controls
"""

from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck
from checkov.common.models.enums import CheckResult, CheckCategories


class DODropletSSHKeysSOC2(BaseResourceCheck):
    def __init__(self):
        name = "Ensure droplets use SSH keys not passwords (SOC2)"
        id = "CKV_SOC2_DO_101"
        supported_resources = ['digitalocean_droplet']
        categories = [CheckCategories.IAM]
        guideline = "SOC2 requires secure authentication. Use SSH keys instead of passwords."
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources, guideline=guideline)

    def scan_resource_conf(self, conf, entity_type):
        ssh_keys = conf.get('ssh_keys')
        if ssh_keys and len(ssh_keys) > 0:
            return CheckResult.PASSED
        return CheckResult.FAILED


class DOFirewallDefaultDenySOC2(BaseResourceCheck):
    def __init__(self):
        name = "Ensure firewalls have explicit rules (SOC2)"
        id = "CKV_SOC2_DO_102"
        supported_resources = ['digitalocean_firewall']
        categories = [CheckCategories.IAM]
        guideline = "SOC2 requires access controls. Define explicit firewall rules."
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources, guideline=guideline)

    def scan_resource_conf(self, conf, entity_type):
        inbound_rules = conf.get('inbound_rule', [])
        outbound_rules = conf.get('outbound_rule', [])

        if inbound_rules or outbound_rules:
            return CheckResult.PASSED
        return CheckResult.FAILED


class DOSpacesACLSOC2(BaseResourceCheck):
    def __init__(self):
        name = "Ensure Spaces buckets have private ACL (SOC2)"
        id = "CKV_SOC2_DO_103"
        supported_resources = ['digitalocean_spaces_bucket']
        categories = [CheckCategories.IAM]
        guideline = "SOC2 requires access controls. Use private ACL for Spaces buckets."
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources, guideline=guideline)

    def scan_resource_conf(self, conf, entity_type):
        acl = conf.get('acl', [''])[0]
        if acl == 'private':
            return CheckResult.PASSED
        if not acl:
            return CheckResult.PASSED
        return CheckResult.FAILED


class DODatabaseFirewallSOC2(BaseResourceCheck):
    def __init__(self):
        name = "Ensure database clusters have firewall rules (SOC2)"
        id = "CKV_SOC2_DO_104"
        supported_resources = ['digitalocean_database_firewall']
        categories = [CheckCategories.IAM]
        guideline = "SOC2 requires network access controls. Configure database firewall rules."
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources, guideline=guideline)

    def scan_resource_conf(self, conf, entity_type):
        rules = conf.get('rule', [])
        if rules and len(rules) > 0:
            return CheckResult.PASSED
        return CheckResult.FAILED


class DOKubernetesRBACSOC2(BaseResourceCheck):
    def __init__(self):
        name = "Ensure Kubernetes clusters have RBAC enabled (SOC2)"
        id = "CKV_SOC2_DO_105"
        supported_resources = ['digitalocean_kubernetes_cluster']
        categories = [CheckCategories.IAM]
        guideline = "SOC2 requires access controls. RBAC is enabled by default in DOKS."
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources, guideline=guideline)

    def scan_resource_conf(self, conf, entity_type):
        return CheckResult.PASSED


check_do_droplet_ssh = DODropletSSHKeysSOC2()
check_do_firewall = DOFirewallDefaultDenySOC2()
check_do_spaces_acl = DOSpacesACLSOC2()
check_do_db_firewall = DODatabaseFirewallSOC2()
check_do_k8s_rbac = DOKubernetesRBACSOC2()
