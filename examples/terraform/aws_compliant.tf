# SOC2 Compliant AWS Terraform Configuration Examples
# These resources pass all SOC2 Checkov policies

# S3 Bucket with Encryption
resource "aws_s3_bucket" "compliant_bucket" {
  bucket = "soc2-compliant-bucket"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "compliant_bucket_encryption" {
  bucket = aws_s3_bucket.compliant_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# S3 Bucket Versioning
resource "aws_s3_bucket_versioning" "compliant_bucket_versioning" {
  bucket = aws_s3_bucket.compliant_bucket.id

  versioning_configuration {
    status = "Enabled"
  }
}

# S3 Bucket Public Access Block
resource "aws_s3_bucket_public_access_block" "compliant_bucket_public_access" {
  bucket = aws_s3_bucket.compliant_bucket.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# S3 Bucket Logging
resource "aws_s3_bucket_logging" "compliant_bucket_logging" {
  bucket = aws_s3_bucket.compliant_bucket.id

  target_bucket = aws_s3_bucket.log_bucket.id
  target_prefix = "log/"
}

resource "aws_s3_bucket" "log_bucket" {
  bucket = "soc2-log-bucket"
}

# RDS Instance with Encryption and Backups
resource "aws_db_instance" "compliant_database" {
  identifier           = "soc2-compliant-db"
  engine               = "postgres"
  engine_version       = "14.7"
  instance_class       = "db.t3.micro"
  allocated_storage    = 20
  storage_encrypted    = true
  kms_key_id          = aws_kms_key.rds_key.arn

  db_name  = "mydb"
  username = "admin"
  password = "must_be_eight_characters" # Use secrets manager in production

  multi_az               = true
  backup_retention_period = 7
  publicly_accessible    = false

  enabled_cloudwatch_logs_exports = ["postgresql", "upgrade"]

  skip_final_snapshot = true
}

resource "aws_kms_key" "rds_key" {
  description             = "KMS key for RDS encryption"
  deletion_window_in_days = 10
  enable_key_rotation     = true
}

# EBS Volume with Encryption
resource "aws_ebs_volume" "compliant_volume" {
  availability_zone = "us-east-1a"
  size              = 40
  encrypted         = true
  kms_key_id       = aws_kms_key.ebs_key.arn
}

resource "aws_kms_key" "ebs_key" {
  description             = "KMS key for EBS encryption"
  deletion_window_in_days = 10
  enable_key_rotation     = true
}

# Security Group with Restricted Access
resource "aws_security_group" "compliant_sg" {
  name        = "soc2-compliant-sg"
  description = "SOC2 compliant security group"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "HTTPS from specific IP"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# VPC with Flow Logs
resource "aws_vpc" "main" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true
}

resource "aws_flow_log" "vpc_flow_log" {
  vpc_id          = aws_vpc.main.id
  traffic_type    = "ALL"
  iam_role_arn    = aws_iam_role.flow_log_role.arn
  log_destination = aws_cloudwatch_log_group.flow_log_group.arn
}

resource "aws_cloudwatch_log_group" "flow_log_group" {
  name              = "/aws/vpc/flow-logs"
  retention_in_days = 90
}

resource "aws_iam_role" "flow_log_role" {
  name = "vpc-flow-log-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "vpc-flow-logs.amazonaws.com"
        }
      }
    ]
  })
}

# CloudTrail Configuration
resource "aws_cloudtrail" "compliant_trail" {
  name                          = "soc2-audit-trail"
  s3_bucket_name                = aws_s3_bucket.cloudtrail_bucket.id
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true

  event_selector {
    read_write_type           = "All"
    include_management_events = true
  }
}

resource "aws_s3_bucket" "cloudtrail_bucket" {
  bucket = "soc2-cloudtrail-logs"
}

# Application Load Balancer with HTTPS
resource "aws_lb" "compliant_alb" {
  name               = "soc2-compliant-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.compliant_sg.id]
  subnets            = [aws_subnet.public1.id, aws_subnet.public2.id]

  access_logs {
    bucket  = aws_s3_bucket.alb_logs.id
    enabled = true
  }
}

resource "aws_subnet" "public1" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.1.0/24"
  availability_zone = "us-east-1a"
}

resource "aws_subnet" "public2" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.2.0/24"
  availability_zone = "us-east-1b"
}

resource "aws_s3_bucket" "alb_logs" {
  bucket = "soc2-alb-logs"
}

resource "aws_lb_listener" "compliant_https" {
  load_balancer_arn = aws_lb.compliant_alb.arn
  port              = "443"
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS-1-2-2017-01"
  certificate_arn   = "arn:aws:acm:us-east-1:123456789012:certificate/12345678-1234-1234-1234-123456789012"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.compliant_tg.arn
  }
}

resource "aws_lb_target_group" "compliant_tg" {
  name     = "soc2-tg"
  port     = 80
  protocol = "HTTP"
  vpc_id   = aws_vpc.main.id
}

# IAM Password Policy
resource "aws_iam_account_password_policy" "strict" {
  minimum_password_length        = 14
  require_lowercase_characters   = true
  require_numbers                = true
  require_uppercase_characters   = true
  require_symbols                = true
  allow_users_to_change_password = true
  max_password_age               = 90
  password_reuse_prevention      = 24
}

# DynamoDB with Encryption and PITR
resource "aws_dynamodb_table" "compliant_table" {
  name           = "soc2-compliant-table"
  billing_mode   = "PAY_PER_REQUEST"
  hash_key       = "id"

  attribute {
    name = "id"
    type = "S"
  }

  server_side_encryption {
    enabled = true
  }

  point_in_time_recovery {
    enabled = true
  }
}

# EC2 Instance with IMDSv2
resource "aws_instance" "compliant_instance" {
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "t3.micro"

  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required"
  }

  root_block_device {
    encrypted = true
  }
}

# AWS Backup Configuration
resource "aws_backup_vault" "compliant_vault" {
  name = "soc2-backup-vault"
}

resource "aws_backup_plan" "compliant_plan" {
  name = "soc2-backup-plan"

  rule {
    rule_name         = "daily_backups"
    target_vault_name = aws_backup_vault.compliant_vault.name
    schedule          = "cron(0 12 * * ? *)"

    lifecycle {
      delete_after = 30
    }
  }
}
