"""
SOC2 Network Security Policies for AWS Terraform Resources
Covers: Security groups, NACLs, VPC configuration
"""

from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck
from checkov.common.models.enums import CheckResult, CheckCategories


class SecurityGroupRestrictedIngressSOC2(BaseResourceCheck):
    def __init__(self):
        name = "Ensure security groups restrict ingress from 0.0.0.0/0 (SOC2)"
        id = "CKV_SOC2_AWS_301"
        supported_resources = ['aws_security_group', 'aws_security_group_rule']
        categories = [CheckCategories.NETWORKING]
        guideline = "SOC2 requires network segmentation. Restrict security group ingress."
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources, guideline=guideline)

    def scan_resource_conf(self, conf):
        # Check for aws_security_group_rule
        rule_type = conf.get('type', [''])[0]
        if rule_type == 'ingress':
            cidr_blocks = conf.get('cidr_blocks', [])
            for cidr_list in cidr_blocks:
                if '0.0.0.0/0' in cidr_list or '::/0' in cidr_list:
                    return CheckResult.FAILED

        # Check for aws_security_group
        ingress_rules = conf.get('ingress', [])
        for rule in ingress_rules:
            cidr_blocks = rule.get('cidr_blocks', [])
            for cidr_list in cidr_blocks:
                if '0.0.0.0/0' in cidr_list or '::/0' in cidr_list:
                    return CheckResult.FAILED

        return CheckResult.PASSED


class SecurityGroupNoSSHFromInternetSOC2(BaseResourceCheck):
    def __init__(self):
        name = "Ensure SSH (port 22) is not open to the internet (SOC2)"
        id = "CKV_SOC2_AWS_302"
        supported_resources = ['aws_security_group', 'aws_security_group_rule']
        categories = [CheckCategories.NETWORKING]
        guideline = "SOC2 requires secure access. Do not expose SSH to the internet."
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources, guideline=guideline)

    def scan_resource_conf(self, conf):
        # Check for aws_security_group_rule
        rule_type = conf.get('type', [''])[0]
        if rule_type == 'ingress':
            from_port = conf.get('from_port', [0])[0]
            to_port = conf.get('to_port', [0])[0]
            cidr_blocks = conf.get('cidr_blocks', [])

            if (from_port <= 22 <= to_port):
                for cidr_list in cidr_blocks:
                    if '0.0.0.0/0' in cidr_list:
                        return CheckResult.FAILED

        # Check for aws_security_group
        ingress_rules = conf.get('ingress', [])
        for rule in ingress_rules:
            from_port = rule.get('from_port', [0])[0]
            to_port = rule.get('to_port', [0])[0]
            cidr_blocks = rule.get('cidr_blocks', [])

            if (from_port <= 22 <= to_port):
                for cidr_list in cidr_blocks:
                    if '0.0.0.0/0' in cidr_list:
                        return CheckResult.FAILED

        return CheckResult.PASSED


class SecurityGroupNoRDPFromInternetSOC2(BaseResourceCheck):
    def __init__(self):
        name = "Ensure RDP (port 3389) is not open to the internet (SOC2)"
        id = "CKV_SOC2_AWS_303"
        supported_resources = ['aws_security_group', 'aws_security_group_rule']
        categories = [CheckCategories.NETWORKING]
        guideline = "SOC2 requires secure access. Do not expose RDP to the internet."
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources, guideline=guideline)

    def scan_resource_conf(self, conf):
        # Check for aws_security_group_rule
        rule_type = conf.get('type', [''])[0]
        if rule_type == 'ingress':
            from_port = conf.get('from_port', [0])[0]
            to_port = conf.get('to_port', [0])[0]
            cidr_blocks = conf.get('cidr_blocks', [])

            if (from_port <= 3389 <= to_port):
                for cidr_list in cidr_blocks:
                    if '0.0.0.0/0' in cidr_list:
                        return CheckResult.FAILED

        # Check for aws_security_group
        ingress_rules = conf.get('ingress', [])
        for rule in ingress_rules:
            from_port = rule.get('from_port', [0])[0]
            to_port = rule.get('to_port', [0])[0]
            cidr_blocks = rule.get('cidr_blocks', [])

            if (from_port <= 3389 <= to_port):
                for cidr_list in cidr_blocks:
                    if '0.0.0.0/0' in cidr_list:
                        return CheckResult.FAILED

        return CheckResult.PASSED


class VPCDefaultSecurityGroupSOC2(BaseResourceCheck):
    def __init__(self):
        name = "Ensure default security group restricts all traffic (SOC2)"
        id = "CKV_SOC2_AWS_304"
        supported_resources = ['aws_default_security_group']
        categories = [CheckCategories.NETWORKING]
        guideline = "SOC2 requires network controls. Restrict default security group."
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources, guideline=guideline)

    def scan_resource_conf(self, conf):
        ingress_rules = conf.get('ingress', [])
        egress_rules = conf.get('egress', [])

        if not ingress_rules and not egress_rules:
            return CheckResult.PASSED
        return CheckResult.FAILED


class NetworkACLRestrictiveSOC2(BaseResourceCheck):
    def __init__(self):
        name = "Ensure Network ACLs do not allow unrestricted ingress (SOC2)"
        id = "CKV_SOC2_AWS_305"
        supported_resources = ['aws_network_acl', 'aws_network_acl_rule']
        categories = [CheckCategories.NETWORKING]
        guideline = "SOC2 requires network controls. Configure restrictive NACLs."
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources, guideline=guideline)

    def scan_resource_conf(self, conf):
        # Check for aws_network_acl_rule
        rule_action = conf.get('rule_action', [''])[0]
        cidr_block = conf.get('cidr_block', [''])[0]

        if rule_action == 'allow' and cidr_block == '0.0.0.0/0':
            return CheckResult.FAILED

        # Check for aws_network_acl
        ingress_rules = conf.get('ingress', [])
        for rule in ingress_rules:
            action = rule.get('action', [''])[0]
            cidr_block = rule.get('cidr_block', [''])[0]

            if action == 'allow' and cidr_block == '0.0.0.0/0':
                return CheckResult.FAILED

        return CheckResult.PASSED


class RDSPublicAccessSOC2(BaseResourceCheck):
    def __init__(self):
        name = "Ensure RDS instances are not publicly accessible (SOC2)"
        id = "CKV_SOC2_AWS_306"
        supported_resources = ['aws_db_instance']
        categories = [CheckCategories.NETWORKING]
        guideline = "SOC2 requires network isolation. RDS instances should not be public."
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources, guideline=guideline)

    def scan_resource_conf(self, conf):
        publicly_accessible = conf.get('publicly_accessible', [False])[0]
        if not publicly_accessible:
            return CheckResult.PASSED
        return CheckResult.FAILED


check_sg_restricted_ingress = SecurityGroupRestrictedIngressSOC2()
check_sg_no_ssh = SecurityGroupNoSSHFromInternetSOC2()
check_sg_no_rdp = SecurityGroupNoRDPFromInternetSOC2()
check_vpc_default_sg = VPCDefaultSecurityGroupSOC2()
check_nacl_restrictive = NetworkACLRestrictiveSOC2()
check_rds_public_access = RDSPublicAccessSOC2()
