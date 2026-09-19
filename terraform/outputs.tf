output "aws_region" {
  description = "Configured AWS deployment region"
  value       = var.aws_region
}

output "risk_register_s3_bucket" {
  description = "S3 bucket storing the automated GRC Risk Register (JSON & CSV)"
  value       = aws_s3_bucket.risk_register_bucket.bucket
}

output "aws_config_delivery_bucket" {
  description = "S3 bucket for AWS Config snapshots and history"
  value       = aws_s3_bucket.config_delivery_bucket.bucket
}

output "lambda_function_name" {
  description = "Name of the Risk Register Logger Lambda function"
  value       = aws_lambda_function.risk_register_logger.function_name
}

output "vulnerable_resources" {
  description = "Identifiers of deliberately misconfigured demo resources"
  value = var.enable_vulnerable_demo_resources ? {
    public_s3_bucket      = aws_s3_bucket.public_demo_bucket[0].bucket
    open_ssh_sec_group    = aws_security_group.open_ssh_sg[0].id
    unencrypted_ebs_id    = aws_ebs_volume.unencrypted_demo_volume[0].id
    iam_user_without_mfa  = aws_iam_user.no_mfa_demo_user[0].name
  } : null
}
