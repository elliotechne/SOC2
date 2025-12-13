"""
SOC2 Network Security Policies for GCP Terraform Resources
Covers: Firewall rules, VPC configuration, network security
"""

from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck
from checkov.common.models.enums import CheckResult, CheckCategories


class GCPFirewallRestrictedIngressSOC2(BaseResourceCheck):
    def __init__(self):
        name = "Ensure firewall rules restrict ingress from 0.0.0.0/0 (SOC2)"
        id = "CKV_SOC2_GCP_301"
        supported_resources = ['google_compute_firewall']
        categories = [CheckCategories.NETWORKING]
        guideline = "SOC2 requires network segmentation. Restrict firewall ingress."
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources, guideline=guideline)

    def scan_resource_conf(self, conf):
        direction = conf.get('direction', ['INGRESS'])[0]
        if direction == 'INGRESS':
            source_ranges = conf.get('source_ranges', [])
            for range_list in source_ranges:
                if '0.0.0.0/0' in range_list:
                    return CheckResult.FAILED

        return CheckResult.PASSED


class GCPFirewallNoSSHFromInternetSOC2(BaseResourceCheck):
    def __init__(self):
        name = "Ensure SSH (port 22) is not open to the internet (SOC2)"
        id = "CKV_SOC2_GCP_302"
        supported_resources = ['google_compute_firewall']
        categories = [CheckCategories.NETWORKING]
        guideline = "SOC2 requires secure access. Do not expose SSH to the internet."
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources, guideline=guideline)

    def scan_resource_conf(self, conf):
        direction = conf.get('direction', ['INGRESS'])[0]
        if direction == 'INGRESS':
            allow_rules = conf.get('allow', [])
            source_ranges = conf.get('source_ranges', [])

            has_public_source = False
            for range_list in source_ranges:
                if '0.0.0.0/0' in range_list:
                    has_public_source = True
                    break

            if has_public_source:
                for rule in allow_rules:
                    ports = rule.get('ports', [])
                    for port_list in ports:
                        if '22' in port_list or 'ssh' in str(rule.get('protocol', [''])[0]).lower():
                            return CheckResult.FAILED

        return CheckResult.PASSED


class GCPFirewallNoRDPFromInternetSOC2(BaseResourceCheck):
    def __init__(self):
        name = "Ensure RDP (port 3389) is not open to the internet (SOC2)"
        id = "CKV_SOC2_GCP_303"
        supported_resources = ['google_compute_firewall']
        categories = [CheckCategories.NETWORKING]
        guideline = "SOC2 requires secure access. Do not expose RDP to the internet."
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources, guideline=guideline)

    def scan_resource_conf(self, conf):
        direction = conf.get('direction', ['INGRESS'])[0]
        if direction == 'INGRESS':
            allow_rules = conf.get('allow', [])
            source_ranges = conf.get('source_ranges', [])

            has_public_source = False
            for range_list in source_ranges:
                if '0.0.0.0/0' in range_list:
                    has_public_source = True
                    break

            if has_public_source:
                for rule in allow_rules:
                    ports = rule.get('ports', [])
                    for port_list in ports:
                        if '3389' in port_list:
                            return CheckResult.FAILED

        return CheckResult.PASSED


class GCPVPCFlowLogsEnabledSOC2(BaseResourceCheck):
    def __init__(self):
        name = "Ensure VPC subnets have flow logs enabled (SOC2)"
        id = "CKV_SOC2_GCP_304"
        supported_resources = ['google_compute_subnetwork']
        categories = [CheckCategories.NETWORKING]
        guideline = "SOC2 requires network monitoring. Enable VPC flow logs."
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources, guideline=guideline)

    def scan_resource_conf(self, conf):
        log_config = conf.get('log_config')
        if log_config:
            return CheckResult.PASSED
        return CheckResult.FAILED


class GCPSQLNoPublicIPSOC2(BaseResourceCheck):
    def __init__(self):
        name = "Ensure Cloud SQL instances do not have public IPs (SOC2)"
        id = "CKV_SOC2_GCP_305"
        supported_resources = ['google_sql_database_instance']
        categories = [CheckCategories.NETWORKING]
        guideline = "SOC2 requires network isolation. Cloud SQL should use private IPs."
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources, guideline=guideline)

    def scan_resource_conf(self, conf):
        settings = conf.get('settings', [])
        if settings:
            for setting in settings:
                ip_configuration = setting.get('ip_configuration', [])
                for ip_config in ip_configuration:
                    ipv4_enabled = ip_config.get('ipv4_enabled', [True])[0]
                    if not ipv4_enabled:
                        return CheckResult.PASSED

        return CheckResult.FAILED


class GCPComputeSerialPortsDisabledSOC2(BaseResourceCheck):
    def __init__(self):
        name = "Ensure compute instances have serial ports disabled (SOC2)"
        id = "CKV_SOC2_GCP_306"
        supported_resources = ['google_compute_instance']
        categories = [CheckCategories.NETWORKING]
        guideline = "SOC2 requires secure access. Disable serial port access."
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources, guideline=guideline)

    def scan_resource_conf(self, conf):
        metadata = conf.get('metadata', [{}])[0]
        serial_port_enable = metadata.get('serial-port-enable', 'FALSE')
        if serial_port_enable == 'FALSE':
            return CheckResult.PASSED
        return CheckResult.FAILED


check_gcp_fw_restricted = GCPFirewallRestrictedIngressSOC2()
check_gcp_fw_no_ssh = GCPFirewallNoSSHFromInternetSOC2()
check_gcp_fw_no_rdp = GCPFirewallNoRDPFromInternetSOC2()
check_gcp_vpc_flow_logs = GCPVPCFlowLogsEnabledSOC2()
check_gcp_sql_no_public_ip = GCPSQLNoPublicIPSOC2()
check_gcp_serial_ports = GCPComputeSerialPortsDisabledSOC2()
