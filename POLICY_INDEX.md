# SOC2 Checkov Policy Index

Complete reference of all custom SOC2 compliance policies organized by provider and category.

## AWS Policies

### Encryption Policies (CKV_SOC2_AWS_001-007)

| Policy ID | Resource Types | Description | SOC2 Control |
|-----------|---------------|-------------|--------------|
| CKV_SOC2_AWS_001 | aws_s3_bucket, aws_s3_bucket_server_side_encryption_configuration | S3 bucket server-side encryption | CC6.6 |
| CKV_SOC2_AWS_002 | aws_ebs_volume, aws_instance | EBS volume encryption | CC6.6 |
| CKV_SOC2_AWS_003 | aws_db_instance, aws_rds_cluster | RDS instance encryption | CC6.6 |
| CKV_SOC2_AWS_004 | aws_efs_file_system | EFS encryption | CC6.6 |
| CKV_SOC2_AWS_005 | aws_lb_listener, aws_alb_listener | ALB/ELB HTTPS/TLS listeners | CC6.7 |
| CKV_SOC2_AWS_006 | aws_redshift_cluster | Redshift cluster encryption | CC6.6 |
| CKV_SOC2_AWS_007 | aws_dynamodb_table | DynamoDB table encryption | CC6.6 |

### Access Control & IAM Policies (CKV_SOC2_AWS_101-106)

| Policy ID | Resource Types | Description | SOC2 Control |
|-----------|---------------|-------------|--------------|
| CKV_SOC2_AWS_101 | aws_iam_account_password_policy | Strong password policy (14+ chars, complexity, 90-day rotation) | CC6.1 |
| CKV_SOC2_AWS_102 | aws_iam_user | IAM user MFA enabled | CC6.1 |
| CKV_SOC2_AWS_103 | aws_s3_bucket_public_access_block, aws_s3_bucket | S3 bucket public access blocked | CC6.1 |
| CKV_SOC2_AWS_104 | aws_iam_role | IAM role assume role policy defined | CC6.1 |
| CKV_SOC2_AWS_105 | aws_iam_account_password_policy | Root account MFA | CC6.1 |
| CKV_SOC2_AWS_106 | aws_instance, aws_launch_template | EC2 IMDSv2 required | CC6.1 |

### Logging & Monitoring Policies (CKV_SOC2_AWS_201-207)

| Policy ID | Resource Types | Description | SOC2 Control |
|-----------|---------------|-------------|--------------|
| CKV_SOC2_AWS_201 | aws_cloudtrail | CloudTrail multi-region enabled | CC7.2 |
| CKV_SOC2_AWS_202 | aws_cloudtrail | CloudTrail log file validation | CC7.2 |
| CKV_SOC2_AWS_203 | aws_flow_log | VPC Flow Logs enabled (ALL traffic) | CC7.2 |
| CKV_SOC2_AWS_204 | aws_s3_bucket, aws_s3_bucket_logging | S3 bucket access logging | CC7.2 |
| CKV_SOC2_AWS_205 | aws_lb, aws_alb, aws_elb | Load balancer access logging | CC7.2 |
| CKV_SOC2_AWS_206 | aws_db_instance | RDS CloudWatch logs enabled | CC7.2 |
| CKV_SOC2_AWS_207 | aws_cloudwatch_log_group | CloudWatch log retention >= 90 days | CC7.2 |

### Network Security Policies (CKV_SOC2_AWS_301-306)

| Policy ID | Resource Types | Description | SOC2 Control |
|-----------|---------------|-------------|--------------|
| CKV_SOC2_AWS_301 | aws_security_group, aws_security_group_rule | No unrestricted ingress (0.0.0.0/0) | CC6.1 |
| CKV_SOC2_AWS_302 | aws_security_group, aws_security_group_rule | SSH (port 22) not open to internet | CC6.1 |
| CKV_SOC2_AWS_303 | aws_security_group, aws_security_group_rule | RDP (port 3389) not open to internet | CC6.1 |
| CKV_SOC2_AWS_304 | aws_default_security_group | Default security group restricts all traffic | CC6.1 |
| CKV_SOC2_AWS_305 | aws_network_acl, aws_network_acl_rule | Network ACL restrictive rules | CC6.1 |
| CKV_SOC2_AWS_306 | aws_db_instance | RDS not publicly accessible | CC6.1 |

### Backup & Recovery Policies (CKV_SOC2_AWS_401-407)

| Policy ID | Resource Types | Description | SOC2 Control |
|-----------|---------------|-------------|--------------|
| CKV_SOC2_AWS_401 | aws_db_instance, aws_rds_cluster | RDS backup retention >= 7 days | A1.2 |
| CKV_SOC2_AWS_402 | aws_s3_bucket, aws_s3_bucket_versioning | S3 bucket versioning enabled | A1.2 |
| CKV_SOC2_AWS_403 | aws_dynamodb_table | DynamoDB point-in-time recovery | A1.2 |
| CKV_SOC2_AWS_404 | aws_dlm_lifecycle_policy | EBS snapshot lifecycle policy | A1.2 |
| CKV_SOC2_AWS_405 | aws_backup_vault | AWS Backup vault configured | A1.2 |
| CKV_SOC2_AWS_406 | aws_backup_plan | AWS Backup plan configured | A1.2 |
| CKV_SOC2_AWS_407 | aws_db_instance | RDS Multi-AZ enabled | A1.2 |

---

## GCP Policies

### Encryption Policies (CKV_SOC2_GCP_001-006)

| Policy ID | Resource Types | Description | SOC2 Control |
|-----------|---------------|-------------|--------------|
| CKV_SOC2_GCP_001 | google_storage_bucket | GCS bucket CMEK encryption | CC6.6 |
| CKV_SOC2_GCP_002 | google_compute_disk, google_compute_instance | Compute disk CMEK encryption | CC6.6 |
| CKV_SOC2_GCP_003 | google_sql_database_instance | Cloud SQL CMEK encryption | CC6.6 |
| CKV_SOC2_GCP_004 | google_bigquery_dataset, google_bigquery_table | BigQuery CMEK encryption | CC6.6 |
| CKV_SOC2_GCP_005 | google_compute_target_https_proxy, google_compute_url_map | Load balancer HTTPS | CC6.7 |
| CKV_SOC2_GCP_006 | google_pubsub_topic | Pub/Sub topic CMEK encryption | CC6.6 |

### Access Control & IAM Policies (CKV_SOC2_GCP_101-105)

| Policy ID | Resource Types | Description | SOC2 Control |
|-----------|---------------|-------------|--------------|
| CKV_SOC2_GCP_101 | google_service_account_key | Service account key rotation policy | CC6.1 |
| CKV_SOC2_GCP_102 | google_project_iam_binding, google_project_iam_member | No primitive roles (Owner/Editor/Viewer) | CC6.1 |
| CKV_SOC2_GCP_103 | google_storage_bucket_iam_binding, google_storage_bucket_iam_member | GCS bucket not public (allUsers/allAuthenticatedUsers) | CC6.1 |
| CKV_SOC2_GCP_104 | google_compute_instance | Compute instance OS Login enabled | CC6.1 |
| CKV_SOC2_GCP_105 | google_project_iam_binding, google_project_iam_member | Service accounts without admin privileges | CC6.1 |

### Logging & Monitoring Policies (CKV_SOC2_GCP_201-206)

| Policy ID | Resource Types | Description | SOC2 Control |
|-----------|---------------|-------------|--------------|
| CKV_SOC2_GCP_201 | google_logging_project_sink | Project logging sink configured | CC7.2 |
| CKV_SOC2_GCP_202 | google_storage_bucket | GCS bucket access logging | CC7.2 |
| CKV_SOC2_GCP_203 | google_sql_database_instance | Cloud SQL audit logging | CC7.2 |
| CKV_SOC2_GCP_204 | google_compute_subnetwork | VPC subnet flow logs enabled | CC7.2 |
| CKV_SOC2_GCP_205 | google_compute_backend_service | Load balancer logging enabled | CC7.2 |
| CKV_SOC2_GCP_206 | google_logging_project_bucket_config | Audit log retention >= 90 days | CC7.2 |

### Network Security Policies (CKV_SOC2_GCP_301-306)

| Policy ID | Resource Types | Description | SOC2 Control |
|-----------|---------------|-------------|--------------|
| CKV_SOC2_GCP_301 | google_compute_firewall | Firewall no unrestricted ingress | CC6.1 |
| CKV_SOC2_GCP_302 | google_compute_firewall | SSH not open to internet | CC6.1 |
| CKV_SOC2_GCP_303 | google_compute_firewall | RDP not open to internet | CC6.1 |
| CKV_SOC2_GCP_304 | google_compute_subnetwork | VPC subnet flow logs | CC6.1 |
| CKV_SOC2_GCP_305 | google_sql_database_instance | Cloud SQL private IP only | CC6.1 |
| CKV_SOC2_GCP_306 | google_compute_instance | Serial ports disabled | CC6.1 |

### Backup & Recovery Policies (CKV_SOC2_GCP_401-406)

| Policy ID | Resource Types | Description | SOC2 Control |
|-----------|---------------|-------------|--------------|
| CKV_SOC2_GCP_401 | google_sql_database_instance | Cloud SQL automated backups | A1.2 |
| CKV_SOC2_GCP_402 | google_compute_resource_policy | Compute disk snapshot schedule | A1.2 |
| CKV_SOC2_GCP_403 | google_storage_bucket | GCS bucket versioning | A1.2 |
| CKV_SOC2_GCP_404 | google_sql_database_instance | Cloud SQL high availability (REGIONAL) | A1.2 |
| CKV_SOC2_GCP_405 | google_bigtable_instance | Bigtable backup configuration | A1.2 |
| CKV_SOC2_GCP_406 | google_sql_database_instance | Cloud SQL point-in-time recovery | A1.2 |

---

## DigitalOcean Policies

### Encryption Policies (CKV_SOC2_DO_001-005)

| Policy ID | Resource Types | Description | SOC2 Control |
|-----------|---------------|-------------|--------------|
| CKV_SOC2_DO_001 | digitalocean_volume | Volume encrypted (ext4 filesystem) | CC6.6 |
| CKV_SOC2_DO_002 | digitalocean_database_cluster | Database SSL/TLS (default) | CC6.7 |
| CKV_SOC2_DO_003 | digitalocean_loadbalancer | Load balancer HTTPS forwarding | CC6.7 |
| CKV_SOC2_DO_004 | digitalocean_spaces_bucket | Spaces bucket encryption (default) | CC6.6 |
| CKV_SOC2_DO_005 | digitalocean_droplet | Droplet SSH keys required | CC6.1 |

### Access Control Policies (CKV_SOC2_DO_101-105)

| Policy ID | Resource Types | Description | SOC2 Control |
|-----------|---------------|-------------|--------------|
| CKV_SOC2_DO_101 | digitalocean_droplet | Droplet SSH keys (no passwords) | CC6.1 |
| CKV_SOC2_DO_102 | digitalocean_firewall | Firewall explicit rules defined | CC6.1 |
| CKV_SOC2_DO_103 | digitalocean_spaces_bucket | Spaces private ACL | CC6.1 |
| CKV_SOC2_DO_104 | digitalocean_database_firewall | Database firewall rules | CC6.1 |
| CKV_SOC2_DO_105 | digitalocean_kubernetes_cluster | Kubernetes RBAC (default) | CC6.1 |

### Logging & Monitoring Policies (CKV_SOC2_DO_201-205)

| Policy ID | Resource Types | Description | SOC2 Control |
|-----------|---------------|-------------|--------------|
| CKV_SOC2_DO_201 | digitalocean_kubernetes_cluster | Kubernetes monitoring (default) | CC7.2 |
| CKV_SOC2_DO_202 | digitalocean_database_cluster | Database logging (default) | CC7.2 |
| CKV_SOC2_DO_203 | digitalocean_monitor_alert | Monitoring alerts configured | CC7.2 |
| CKV_SOC2_DO_204 | digitalocean_loadbalancer | Load balancer health checks | CC7.2 |
| CKV_SOC2_DO_205 | digitalocean_firewall | Firewall rules for monitoring | CC7.2 |

### Network Security Policies (CKV_SOC2_DO_301-306)

| Policy ID | Resource Types | Description | SOC2 Control |
|-----------|---------------|-------------|--------------|
| CKV_SOC2_DO_301 | digitalocean_firewall | Firewall restricted ingress | CC6.1 |
| CKV_SOC2_DO_302 | digitalocean_firewall | SSH not open to internet | CC6.1 |
| CKV_SOC2_DO_303 | digitalocean_database_cluster | Database private networking | CC6.1 |
| CKV_SOC2_DO_304 | digitalocean_kubernetes_cluster | Kubernetes VPC networking | CC6.1 |
| CKV_SOC2_DO_305 | digitalocean_droplet | Droplet private networking | CC6.1 |
| CKV_SOC2_DO_306 | digitalocean_vpc | VPC configured with IP range | CC6.1 |

### Backup & Recovery Policies (CKV_SOC2_DO_401-406)

| Policy ID | Resource Types | Description | SOC2 Control |
|-----------|---------------|-------------|--------------|
| CKV_SOC2_DO_401 | digitalocean_droplet | Droplet backups enabled | A1.2 |
| CKV_SOC2_DO_402 | digitalocean_database_cluster | Database automated backups (default) | A1.2 |
| CKV_SOC2_DO_403 | digitalocean_volume_snapshot | Volume snapshot policy | A1.2 |
| CKV_SOC2_DO_404 | digitalocean_kubernetes_cluster | Kubernetes backup strategy | A1.2 |
| CKV_SOC2_DO_405 | digitalocean_spaces_bucket | Spaces lifecycle policy | A1.2 |
| CKV_SOC2_DO_406 | digitalocean_database_cluster | Database high availability (2+ nodes) | A1.2 |

---

## SOC2 Trust Services Criteria Mapping

### CC6.1 - Logical and Physical Access Controls
- All Access Control & IAM policies
- All Network Security policies

### CC6.6 - Encryption of Data at Rest
- All Encryption policies (data at rest)

### CC6.7 - Encryption of Data in Transit
- HTTPS/TLS policies
- Load balancer encryption policies

### CC7.2 - System Monitoring
- All Logging & Monitoring policies

### A1.2 - Backup and Recovery
- All Backup & Recovery policies

## Policy Statistics

| Provider | Total Policies | Encryption | Access Control | Logging | Network | Backup |
|----------|----------------|------------|----------------|---------|---------|--------|
| AWS | 33 | 7 | 6 | 7 | 6 | 7 |
| GCP | 29 | 6 | 5 | 6 | 6 | 6 |
| DigitalOcean | 27 | 5 | 5 | 5 | 6 | 6 |
| **Total** | **89** | **18** | **16** | **18** | **18** | **19** |

## Usage Examples

### Run specific policy
```bash
checkov -f main.tf --external-checks-dir ./checkov_policies --check CKV_SOC2_AWS_001
```

### Run all encryption policies
```bash
checkov -d ./terraform --external-checks-dir ./checkov_policies --check CKV_SOC2_AWS_00[1-7],CKV_SOC2_GCP_00[1-6],CKV_SOC2_DO_00[1-5]
```

### Skip specific policies
```bash
checkov -d ./terraform --external-checks-dir ./checkov_policies --skip-check CKV_SOC2_AWS_101
```
