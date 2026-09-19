# S3 Bucket for AWS Config Delivery
resource "random_string" "config_suffix" {
  length  = 8
  special = false
  upper   = false
}

resource "aws_s3_bucket" "config_delivery_bucket" {
  bucket        = "${var.project_name}-config-${random_string.config_suffix.result}"
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "config_delivery_pab" {
  bucket                  = aws_s3_bucket.config_delivery_bucket.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

data "aws_caller_identity" "current" {}

resource "aws_s3_bucket_server_side_encryption_configuration" "config_delivery_encryption" {
  bucket = aws_s3_bucket.config_delivery_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_policy" "config_delivery_policy" {
  bucket     = aws_s3_bucket.config_delivery_bucket.id
  depends_on = [aws_s3_bucket_public_access_block.config_delivery_pab]

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AWSConfigBucketPermissionsCheck"
        Effect = "Allow"
        Principal = {
          Service = "config.amazonaws.com"
        }
        Action = [
          "s3:GetBucketAcl",
          "s3:ListBucket"
        ]
        Resource = aws_s3_bucket.config_delivery_bucket.arn
      },
      {
        Sid    = "AWSConfigBucketDelivery"
        Effect = "Allow"
        Principal = {
          Service = "config.amazonaws.com"
        }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.config_delivery_bucket.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/Config/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl" = "bucket-owner-full-control"
          }
        }
      }
    ]
  })
}

# IAM Role for AWS Config
resource "aws_iam_role" "config_role" {
  name = "${var.project_name}-aws-config-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "config.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "config_policy_attachment" {
  role       = aws_iam_role.config_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWS_ConfigRole"
}

resource "aws_iam_role_policy" "config_s3_policy" {
  name = "${var.project_name}-config-s3-policy"
  role = aws_iam_role.config_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["s3:PutObject", "s3:PutObjectAcl"]
        Resource = "${aws_s3_bucket.config_delivery_bucket.arn}/AWSLogs/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl" = "bucket-owner-full-control"
          }
        }
      },
      {
        Effect   = "Allow"
        Action   = "s3:GetBucketAcl"
        Resource = aws_s3_bucket.config_delivery_bucket.arn
      }
    ]
  })
}

# AWS Config Recorder & Delivery Channel
resource "aws_config_configuration_recorder" "recorder" {
  name     = "${var.project_name}-recorder"
  role_arn = aws_iam_role.config_role.arn

  recording_group {
    all_supported                 = true
    include_global_resource_types = true
  }
}

resource "aws_config_delivery_channel" "delivery" {
  name           = "${var.project_name}-delivery-channel"
  s3_bucket_name = aws_s3_bucket.config_delivery_bucket.bucket
  depends_on = [
    aws_config_configuration_recorder.recorder,
    aws_s3_bucket_policy.config_delivery_policy
  ]
}

resource "aws_config_configuration_recorder_status" "recorder_status" {
  name       = aws_config_configuration_recorder.recorder.name
  is_enabled = true
  depends_on = [aws_config_delivery_channel.delivery]
}

# AWS Config Managed Rules targeting the demo misconfigurations

# 1. Detect public S3 buckets
resource "aws_config_config_rule" "s3_bucket_public_read_prohibited" {
  name        = "s3-bucket-public-read-prohibited"
  description = "Checks that your Amazon S3 buckets do not allow public read access."

  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_PUBLIC_READ_PROHIBITED"
  }

  depends_on = [aws_config_configuration_recorder_status.recorder_status]
}

# 2. Detect SSH open to 0.0.0.0/0
resource "aws_config_config_rule" "restricted_ssh" {
  name        = "restricted-ssh"
  description = "Checks whether security groups in use disallow unrestricted incoming SSH traffic (0.0.0.0/0)."

  source {
    owner             = "AWS"
    source_identifier = "INCOMING_SSH_DISABLED"
  }

  depends_on = [aws_config_configuration_recorder_status.recorder_status]
}

# 3. Detect unencrypted EBS volumes
resource "aws_config_config_rule" "encrypted_volumes" {
  name        = "encrypted-volumes"
  description = "Checks whether EBS volumes that are in an attached state or standalone are encrypted."

  source {
    owner             = "AWS"
    source_identifier = "ENCRYPTED_VOLUMES"
  }

  depends_on = [aws_config_configuration_recorder_status.recorder_status]
}

# 4. Detect IAM users without MFA
resource "aws_config_config_rule" "iam_user_mfa_enabled" {
  name        = "iam-user-mfa-enabled"
  description = "Checks whether the AWS Identity and Access Management (IAM) users have multi-factor authentication (MFA) enabled."

  source {
    owner             = "AWS"
    source_identifier = "IAM_USER_MFA_ENABLED"
  }

  depends_on = [aws_config_configuration_recorder_status.recorder_status]
}
