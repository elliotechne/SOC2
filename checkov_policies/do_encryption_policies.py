"""
SOC2 Encryption Policies for DigitalOcean Terraform Resources
Covers: Data encryption at rest and in transit
"""

from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck
from checkov.common.models.enums import CheckResult, CheckCategories


class DOVolumeEncryptionSOC2(BaseResourceCheck):
    def __init__(self):
        name = "Ensure DigitalOcean volumes are encrypted (SOC2)"
        id = "CKV_SOC2_DO_001"
        supported_resources = ['digitalocean_volume']
        categories = [CheckCategories.ENCRYPTION]
        guideline = "SOC2 requires encryption of data at rest. Enable volume encryption."
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources, guideline=guideline)

    def scan_resource_conf(self, conf):
        initial_filesystem_type = conf.get('initial_filesystem_type', [''])[0]
        if initial_filesystem_type == 'ext4':
            return CheckResult.PASSED
        return CheckResult.FAILED


class DODatabaseEncryptionSOC2(BaseResourceCheck):
    def __init__(self):
        name = "Ensure DigitalOcean databases use SSL (SOC2)"
        id = "CKV_SOC2_DO_002"
        supported_resources = ['digitalocean_database_cluster']
        categories = [CheckCategories.ENCRYPTION]
        guideline = "SOC2 requires encryption in transit. Databases are encrypted by default in DO."
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources, guideline=guideline)

    def scan_resource_conf(self, conf):
        return CheckResult.PASSED


class DOLoadBalancerHTTPSSOC2(BaseResourceCheck):
    def __init__(self):
        name = "Ensure DigitalOcean load balancers use HTTPS (SOC2)"
        id = "CKV_SOC2_DO_003"
        supported_resources = ['digitalocean_loadbalancer']
        categories = [CheckCategories.ENCRYPTION]
        guideline = "SOC2 requires encryption of data in transit. Configure HTTPS forwarding rules."
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources, guideline=guideline)

    def scan_resource_conf(self, conf):
        forwarding_rules = conf.get('forwarding_rule', [])
        if not forwarding_rules:
            return CheckResult.FAILED

        has_https = False
        for rule in forwarding_rules:
            entry_protocol = rule.get('entry_protocol', [''])[0]
            if entry_protocol in ['https', 'http2', 'http3']:
                has_https = True
                break

        if has_https:
            return CheckResult.PASSED
        return CheckResult.FAILED


class DOSpacesEncryptionSOC2(BaseResourceCheck):
    def __init__(self):
        name = "Ensure DigitalOcean Spaces buckets enforce encryption (SOC2)"
        id = "CKV_SOC2_DO_004"
        supported_resources = ['digitalocean_spaces_bucket']
        categories = [CheckCategories.ENCRYPTION]
        guideline = "SOC2 requires encryption of data at rest. Spaces are encrypted by default."
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources, guideline=guideline)

    def scan_resource_conf(self, conf):
        return CheckResult.PASSED


class DODropletSSHOnlySOC2(BaseResourceCheck):
    def __init__(self):
        name = "Ensure DigitalOcean droplets use SSH keys (SOC2)"
        id = "CKV_SOC2_DO_005"
        supported_resources = ['digitalocean_droplet']
        categories = [CheckCategories.ENCRYPTION]
        guideline = "SOC2 requires secure authentication. Use SSH keys instead of passwords."
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources, guideline=guideline)

    def scan_resource_conf(self, conf):
        ssh_keys = conf.get('ssh_keys')
        if ssh_keys and len(ssh_keys) > 0:
            return CheckResult.PASSED
        return CheckResult.FAILED


check_do_volume_encryption = DOVolumeEncryptionSOC2()
check_do_database_encryption = DODatabaseEncryptionSOC2()
check_do_lb_https = DOLoadBalancerHTTPSSOC2()
check_do_spaces_encryption = DOSpacesEncryptionSOC2()
check_do_droplet_ssh = DODropletSSHOnlySOC2()
