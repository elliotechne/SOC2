"""
SOC2 Logging and Monitoring Policies for AWS Terraform Resources
Covers: CloudTrail, VPC Flow Logs, S3 access logging, CloudWatch
"""

from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck
from checkov.common.models.enums import CheckResult, CheckCategories


class CloudTrailEnabledSOC2(BaseResourceCheck):
    def __init__(self):
        name = "Ensure CloudTrail is enabled (SOC2)"
        id = "CKV_SOC2_AWS_201"
        supported_resources = ['aws_cloudtrail']
        categories = [CheckCategories.LOGGING]
        guideline = "SOC2 requires audit logging. Enable CloudTrail for all regions."
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources, guideline=guideline)

    def scan_resource_conf(self, conf):
        is_multi_region = conf.get('is_multi_region_trail', [False])[0]
        include_global_events = conf.get('include_global_service_events', [False])[0]

        if is_multi_region and include_global_events:
            return CheckResult.PASSED
        return CheckResult.FAILED


class CloudTrailLogValidationSOC2(BaseResourceCheck):
    def __init__(self):
        name = "Ensure CloudTrail log file validation is enabled (SOC2)"
        id = "CKV_SOC2_AWS_202"
        supported_resources = ['aws_cloudtrail']
        categories = [CheckCategories.LOGGING]
        guideline = "SOC2 requires log integrity. Enable log file validation."
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources, guideline=guideline)

    def scan_resource_conf(self, conf):
        log_validation = conf.get('enable_log_file_validation', [False])[0]
        if log_validation:
            return CheckResult.PASSED
        return CheckResult.FAILED


class VPCFlowLogsSOC2(BaseResourceCheck):
    def __init__(self):
        name = "Ensure VPC Flow Logs are enabled (SOC2)"
        id = "CKV_SOC2_AWS_203"
        supported_resources = ['aws_flow_log']
        categories = [CheckCategories.LOGGING]
        guideline = "SOC2 requires network traffic logging. Enable VPC Flow Logs."
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources, guideline=guideline)

    def scan_resource_conf(self, conf):
        traffic_type = conf.get('traffic_type', [''])[0]
        if traffic_type == 'ALL':
            return CheckResult.PASSED
        return CheckResult.FAILED


class S3BucketAccessLoggingSOC2(BaseResourceCheck):
    def __init__(self):
        name = "Ensure S3 buckets have access logging enabled (SOC2)"
        id = "CKV_SOC2_AWS_204"
        supported_resources = ['aws_s3_bucket', 'aws_s3_bucket_logging']
        categories = [CheckCategories.LOGGING]
        guideline = "SOC2 requires access logging. Enable S3 bucket access logging."
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources, guideline=guideline)

    def scan_resource_conf(self, conf):
        # Check for target_bucket (aws_s3_bucket_logging)
        target_bucket = conf.get('target_bucket')
        if target_bucket:
            return CheckResult.PASSED

        # Check for logging (aws_s3_bucket)
        logging = conf.get('logging')
        if logging:
            return CheckResult.PASSED

        return CheckResult.FAILED


class ALBAccessLoggingSOC2(BaseResourceCheck):
    def __init__(self):
        name = "Ensure ALB/ELB access logging is enabled (SOC2)"
        id = "CKV_SOC2_AWS_205"
        supported_resources = ['aws_lb', 'aws_alb', 'aws_elb']
        categories = [CheckCategories.LOGGING]
        guideline = "SOC2 requires access logging. Enable load balancer access logs."
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources, guideline=guideline)

    def scan_resource_conf(self, conf):
        access_logs = conf.get('access_logs', [])
        if access_logs:
            for log_config in access_logs:
                if log_config.get('enabled', [False])[0]:
                    return CheckResult.PASSED

        return CheckResult.FAILED


class RDSLoggingSOC2(BaseResourceCheck):
    def __init__(self):
        name = "Ensure RDS instances have logging enabled (SOC2)"
        id = "CKV_SOC2_AWS_206"
        supported_resources = ['aws_db_instance']
        categories = [CheckCategories.LOGGING]
        guideline = "SOC2 requires database logging. Enable RDS enhanced monitoring and logs."
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources, guideline=guideline)

    def scan_resource_conf(self, conf):
        enabled_cloudwatch_logs = conf.get('enabled_cloudwatch_logs_exports', [])
        if enabled_cloudwatch_logs and len(enabled_cloudwatch_logs) > 0:
            return CheckResult.PASSED
        return CheckResult.FAILED


class CloudWatchLogRetentionSOC2(BaseResourceCheck):
    def __init__(self):
        name = "Ensure CloudWatch log groups have retention policy (SOC2)"
        id = "CKV_SOC2_AWS_207"
        supported_resources = ['aws_cloudwatch_log_group']
        categories = [CheckCategories.LOGGING]
        guideline = "SOC2 requires log retention. Set retention policy for CloudWatch logs."
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources, guideline=guideline)

    def scan_resource_conf(self, conf):
        retention_days = conf.get('retention_in_days', [0])[0]
        if retention_days >= 90:
            return CheckResult.PASSED
        return CheckResult.FAILED


check_cloudtrail_enabled = CloudTrailEnabledSOC2()
check_cloudtrail_validation = CloudTrailLogValidationSOC2()
check_vpc_flow_logs = VPCFlowLogsSOC2()
check_s3_access_logging = S3BucketAccessLoggingSOC2()
check_alb_access_logging = ALBAccessLoggingSOC2()
check_rds_logging = RDSLoggingSOC2()
check_cloudwatch_retention = CloudWatchLogRetentionSOC2()
