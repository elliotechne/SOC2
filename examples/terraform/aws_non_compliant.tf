# SOC2 Non-Compliant AWS Terraform Configuration Examples
# These resources fail SOC2 Checkov policies - USE FOR TESTING ONLY

# S3 Bucket WITHOUT Encryption (FAILS CKV_SOC2_AWS_001)
resource "aws_s3_bucket" "non_compliant_bucket" {
  bucket = "soc2-non-compliant-bucket"
  # Missing server_side_encryption_configuration
}

# S3 Bucket WITHOUT Versioning (FAILS CKV_SOC2_AWS_402)
# Versioning not configured

# S3 Bucket WITH Public Access (FAILS CKV_SOC2_AWS_103)
resource "aws_s3_bucket_public_access_block" "non_compliant_public" {
  bucket = aws_s3_bucket.non_compliant_bucket.id

  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

# RDS WITHOUT Encryption (FAILS CKV_SOC2_AWS_003)
resource "aws_db_instance" "non_compliant_db" {
  identifier           = "soc2-non-compliant-db"
  engine               = "postgres"
  engine_version       = "14.7"
  instance_class       = "db.t3.micro"
  allocated_storage    = 20
  storage_encrypted    = false # NOT ENCRYPTED

  db_name  = "mydb"
  username = "admin"
  password = "password123"

  publicly_accessible     = true # PUBLICLY ACCESSIBLE (FAILS CKV_SOC2_AWS_306)
  backup_retention_period = 0    # NO BACKUPS (FAILS CKV_SOC2_AWS_401)
  multi_az                = false # NOT MULTI-AZ (FAILS CKV_SOC2_AWS_407)

  skip_final_snapshot = true
}

# EBS Volume WITHOUT Encryption (FAILS CKV_SOC2_AWS_002)
resource "aws_ebs_volume" "non_compliant_volume" {
  availability_zone = "us-east-1a"
  size              = 40
  encrypted         = false # NOT ENCRYPTED
}

# Security Group with Open SSH (FAILS CKV_SOC2_AWS_302)
resource "aws_security_group" "non_compliant_sg" {
  name        = "soc2-non-compliant-sg"
  description = "Non-compliant security group"
  vpc_id      = aws_vpc.non_compliant_vpc.id

  ingress {
    description = "SSH from anywhere"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # OPEN TO INTERNET
  }

  ingress {
    description = "RDP from anywhere"
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # OPEN TO INTERNET (FAILS CKV_SOC2_AWS_303)
  }
}

# VPC WITHOUT Flow Logs (FAILS CKV_SOC2_AWS_203)
resource "aws_vpc" "non_compliant_vpc" {
  cidr_block = "10.0.0.0/16"
  # No flow logs configured
}

# CloudWatch Log Group with Short Retention (FAILS CKV_SOC2_AWS_207)
resource "aws_cloudwatch_log_group" "non_compliant_logs" {
  name              = "/aws/lambda/function"
  retention_in_days = 7 # Less than 90 days
}

# CloudTrail NOT Multi-Region (FAILS CKV_SOC2_AWS_201)
resource "aws_cloudtrail" "non_compliant_trail" {
  name                          = "non-compliant-trail"
  s3_bucket_name                = aws_s3_bucket.non_compliant_bucket.id
  include_global_service_events = false # NOT INCLUDING GLOBAL EVENTS
  is_multi_region_trail         = false # NOT MULTI-REGION
  enable_log_file_validation    = false # NO LOG VALIDATION (FAILS CKV_SOC2_AWS_202)
}

# Load Balancer with HTTP (FAILS CKV_SOC2_AWS_005)
resource "aws_lb" "non_compliant_alb" {
  name               = "non-compliant-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.non_compliant_sg.id]
  subnets            = [aws_subnet.non_compliant1.id, aws_subnet.non_compliant2.id]

  # No access logs configured (FAILS CKV_SOC2_AWS_205)
}

resource "aws_subnet" "non_compliant1" {
  vpc_id            = aws_vpc.non_compliant_vpc.id
  cidr_block        = "10.0.1.0/24"
  availability_zone = "us-east-1a"
}

resource "aws_subnet" "non_compliant2" {
  vpc_id            = aws_vpc.non_compliant_vpc.id
  cidr_block        = "10.0.2.0/24"
  availability_zone = "us-east-1b"
}

resource "aws_lb_listener" "non_compliant_http" {
  load_balancer_arn = aws_lb.non_compliant_alb.arn
  port              = "80"
  protocol          = "HTTP" # NOT HTTPS

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.non_compliant_tg.arn
  }
}

resource "aws_lb_target_group" "non_compliant_tg" {
  name     = "non-compliant-tg"
  port     = 80
  protocol = "HTTP"
  vpc_id   = aws_vpc.non_compliant_vpc.id
}

# Weak IAM Password Policy (FAILS CKV_SOC2_AWS_101)
resource "aws_iam_account_password_policy" "weak" {
  minimum_password_length        = 8  # Too short
  require_lowercase_characters   = false
  require_numbers                = false
  require_uppercase_characters   = false
  require_symbols                = false
  allow_users_to_change_password = true
  max_password_age               = 365 # Too long
}

# DynamoDB WITHOUT Encryption (FAILS CKV_SOC2_AWS_007)
resource "aws_dynamodb_table" "non_compliant_table" {
  name           = "non-compliant-table"
  billing_mode   = "PAY_PER_REQUEST"
  hash_key       = "id"

  attribute {
    name = "id"
    type = "S"
  }

  # No server_side_encryption configured
  # No point_in_time_recovery (FAILS CKV_SOC2_AWS_403)
}

# EC2 Instance WITHOUT IMDSv2 (FAILS CKV_SOC2_AWS_106)
resource "aws_instance" "non_compliant_instance" {
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "t3.micro"

  # No metadata_options configured - defaults to IMDSv1

  root_block_device {
    encrypted = false # NOT ENCRYPTED (FAILS CKV_SOC2_AWS_002)
  }
}

# Default Security Group with Rules (FAILS CKV_SOC2_AWS_304)
resource "aws_default_security_group" "default" {
  vpc_id = aws_vpc.non_compliant_vpc.id

  ingress {
    protocol  = -1
    self      = true
    from_port = 0
    to_port   = 0
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
