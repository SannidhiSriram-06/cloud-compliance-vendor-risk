# ==============================================================================
# DELIBERATELY MISCONFIGURED RESOURCES FOR COMPLIANCE AUDITING DEMO
# WARNING: Deploy only in a controlled sandbox environment!
# ==============================================================================

# Data source for default VPC and AZs
data "aws_vpc" "default" {
  default = true
}

data "aws_availability_zones" "available" {
  state = "available"
}

# ------------------------------------------------------------------------------
# 1. Misconfigured S3 Bucket (Public Read Enabled)
# Detectable by: CIS AWS Benchmark 2.1.5, AWS Config s3-bucket-public-read-prohibited
# Mappings: ISO 27001 A.8.24 / A.5.15, NIST CSF PR.DS-1 / PR.AC-3
# ------------------------------------------------------------------------------
resource "random_string" "vuln_bucket_suffix" {
  count   = var.enable_vulnerable_demo_resources ? 1 : 0
  length  = 8
  special = false
  upper   = false
}

resource "aws_s3_bucket" "public_demo_bucket" {
  count         = var.enable_vulnerable_demo_resources ? 1 : 0
  bucket        = "${var.project_name}-public-demo-${random_string.vuln_bucket_suffix[0].result}"
  force_destroy = true

  tags = {
    ComplianceFinding = "S3-PUBLIC-READ"
    RiskLevel         = "High"
    DemoResource      = "true"
  }
}

resource "aws_s3_bucket_public_access_block" "public_demo_pab" {
  count                   = var.enable_vulnerable_demo_resources ? 1 : 0
  bucket                  = aws_s3_bucket.public_demo_bucket[0].id
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

resource "aws_s3_bucket_policy" "public_demo_policy" {
  count      = var.enable_vulnerable_demo_resources ? 1 : 0
  bucket     = aws_s3_bucket.public_demo_bucket[0].id
  depends_on = [aws_s3_bucket_public_access_block.public_demo_pab]

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "PublicReadGetObjectDemo"
        Effect    = "Allow"
        Principal = "*"
        Action    = "s3:GetObject"
        Resource  = "${aws_s3_bucket.public_demo_bucket[0].arn}/*"
      }
    ]
  })
}

# ------------------------------------------------------------------------------
# 2. Insecure Security Group (Port 22 SSH open to 0.0.0.0/0)
# Detectable by: CIS AWS Benchmark 5.2 / 4.1, AWS Config restricted-ssh
# Mappings: ISO 27001 A.8.20 / A.8.21, NIST CSF PR.AC-5 / PR.PT-4
# ------------------------------------------------------------------------------
resource "aws_security_group" "open_ssh_sg" {
  count       = var.enable_vulnerable_demo_resources ? 1 : 0
  name        = "${var.project_name}-open-ssh-sg"
  description = "DEMO VULNERABILITY: Insecure Security Group with unrestricted SSH (0.0.0.0/0)"
  vpc_id      = data.aws_vpc.default.id

  ingress {
    description = "Unrestricted SSH access for compliance audit demonstration"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "Allow all outbound traffic"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    ComplianceFinding = "EC2-OPEN-SSH"
    RiskLevel         = "High"
    DemoResource      = "true"
  }
}

data "aws_ssm_parameter" "al2023_ami" {
  name = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
}

data "aws_subnets" "default" {
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.default.id]
  }
}

data "aws_subnet" "selected_default" {
  id = data.aws_subnets.default.ids[0]
}

# ------------------------------------------------------------------------------
# 3. Unencrypted EBS Volume & Demo EC2 Instance
# Detectable by: CIS AWS Benchmark 2.2.1, AWS Config encrypted-volumes
# Mappings: ISO 27001 A.8.24 (Use of Cryptography), NIST CSF PR.DS-1
# ------------------------------------------------------------------------------
resource "aws_security_group" "demo_instance_sg" {
  count       = var.enable_vulnerable_demo_resources ? 1 : 0
  name        = "${var.project_name}-isolated-instance-sg"
  description = "Isolated security group with no ingress rules for demo instance"
  vpc_id      = data.aws_vpc.default.id

  egress {
    description = "Allow all outbound traffic"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name         = "${var.project_name}-isolated-instance-sg"
    DemoResource = "true"
  }
}

resource "aws_instance" "demo_host" {
  count                       = var.enable_vulnerable_demo_resources ? 1 : 0
  ami                         = data.aws_ssm_parameter.al2023_ami.value
  instance_type               = "t3.nano"
  subnet_id                   = data.aws_subnet.selected_default.id
  associate_public_ip_address = false
  vpc_security_group_ids      = [aws_security_group.demo_instance_sg[0].id]

  metadata_options {
    http_tokens = "required"
  }

  root_block_device {
    encrypted = true
  }

  tags = {
    Name         = "${var.project_name}-demo-host"
    DemoResource = "true"
  }
}

resource "aws_ebs_volume" "unencrypted_demo_volume" {
  count             = var.enable_vulnerable_demo_resources ? 1 : 0
  availability_zone = aws_instance.demo_host[0].availability_zone
  size              = 1
  encrypted         = false # Explicitly unencrypted for demo
  type              = "gp3"

  tags = {
    Name              = "${var.project_name}-unencrypted-volume"
    ComplianceFinding = "EBS-UNENCRYPTED"
    RiskLevel         = "Medium"
    DemoResource      = "true"
  }
}

resource "aws_volume_attachment" "unencrypted_demo_attachment" {
  count       = var.enable_vulnerable_demo_resources ? 1 : 0
  device_name = "/dev/sdf"
  volume_id   = aws_ebs_volume.unencrypted_demo_volume[0].id
  instance_id = aws_instance.demo_host[0].id
}

# ------------------------------------------------------------------------------
# 4. IAM User with Console Access and No MFA Enforced
# Detectable by: CIS AWS Benchmark 1.5 / 1.10, AWS Config iam-user-mfa-enabled
# Mappings: ISO 27001 A.5.15 / A.5.17, NIST CSF PR.AC-1 / PR.AC-7
# ------------------------------------------------------------------------------
resource "aws_iam_user" "no_mfa_demo_user" {
  count         = var.enable_vulnerable_demo_resources ? 1 : 0
  name          = "${var.project_name}-contractor-no-mfa"
  force_destroy = true

  tags = {
    ComplianceFinding = "IAM-NO-MFA"
    RiskLevel         = "High"
    DemoResource      = "true"
  }
}

resource "aws_iam_access_key" "demo_user_key" {
  count = var.enable_vulnerable_demo_resources ? 1 : 0
  user  = aws_iam_user.no_mfa_demo_user[0].name
}

resource "aws_iam_user_login_profile" "demo_user_login" {
  count                   = var.enable_vulnerable_demo_resources ? 1 : 0
  user                    = aws_iam_user.no_mfa_demo_user[0].name
  password_reset_required = false
  # Password generated for demonstration purposes
  password_length = 16
}
