# S3 Bucket for Risk Register JSON and CSV outputs
resource "random_string" "risk_reg_suffix" {
  length  = 8
  special = false
  upper   = false
}

resource "aws_s3_bucket" "risk_register_bucket" {
  bucket        = "${var.project_name}-risk-register-${random_string.risk_reg_suffix.result}"
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "risk_register_pab" {
  bucket                  = aws_s3_bucket.risk_register_bucket.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "risk_register_enc" {
  bucket = aws_s3_bucket.risk_register_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# Package Lambda code
data "archive_file" "lambda_zip" {
  type        = "zip"
  source_file = "${path.module}/../lambda/risk_register_processor.py"
  output_path = "${path.module}/lambda_risk_register.zip"
}

# Lambda Execution IAM Role
resource "aws_iam_role" "lambda_role" {
  name = "${var.project_name}-risk-register-lambda-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy" "lambda_policy" {
  name = "${var.project_name}-risk-register-lambda-policy"
  role = aws_iam_role.lambda_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:*:*:*"
      },
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:ListBucket"
        ]
        Resource = [
          aws_s3_bucket.risk_register_bucket.arn,
          "${aws_s3_bucket.risk_register_bucket.arn}/*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "securityhub:GetFindings",
          "config:GetComplianceDetailsByConfigRule"
        ]
        Resource = "*"
      }
    ]
  })
}

# Lambda Function
resource "aws_lambda_function" "risk_register_logger" {
  filename         = data.archive_file.lambda_zip.output_path
  function_name    = "${var.project_name}-risk-register-logger"
  role             = aws_iam_role.lambda_role.arn
  handler          = "risk_register_processor.lambda_handler"
  runtime          = "python3.11"
  timeout          = 60
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256

  environment {
    variables = {
      RISK_REGISTER_BUCKET = aws_s3_bucket.risk_register_bucket.bucket
      ENVIRONMENT          = var.environment
      APP_NAME             = var.project_name
    }
  }
}

resource "aws_cloudwatch_log_group" "lambda_logs" {
  name              = "/aws/lambda/${aws_lambda_function.risk_register_logger.function_name}"
  retention_in_days = 14
}

# EventBridge Rule: Triggered on Security Hub Findings & AWS Config Compliance changes
resource "aws_cloudwatch_event_rule" "compliance_findings_rule" {
  name        = "${var.project_name}-compliance-evaluations"
  description = "Captures AWS Security Hub and AWS Config compliance failures and routes to Risk Register Lambda"

  event_pattern = jsonencode({
    source = [
      "aws.securityhub",
      "aws.config"
    ]
    detail-type = [
      "Security Hub Findings - Imported",
      "Config Rules Compliance Change"
    ]
  })
}

resource "aws_cloudwatch_event_target" "lambda_target" {
  rule      = aws_cloudwatch_event_rule.compliance_findings_rule.name
  target_id = "TriggerRiskRegisterLambda"
  arn       = aws_lambda_function.risk_register_logger.arn
}

resource "aws_lambda_permission" "allow_eventbridge" {
  statement_id  = "AllowExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.risk_register_logger.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.compliance_findings_rule.arn
}
