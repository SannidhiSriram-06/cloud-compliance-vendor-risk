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

resource "aws_cloudwatch_log_group" "lambda_logs" {
  name              = "/aws/lambda/${var.project_name}-risk-register-logger"
  retention_in_days = 14
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
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "${aws_cloudwatch_log_group.lambda_logs.arn}:*"
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
        # Resolves AWS::IAM::User unique IDs (AIDA...) to human-readable user names
        # for cross-source deduplication. AWS Config BatchGetResourceConfig does not
        # support resource-level ARN constraints and requires Resource = "*".
        Effect   = "Allow"
        Action   = ["config:BatchGetResourceConfig"]
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

# EventBridge Rule A: Security Hub FAILED Findings (Conditional on enable_security_hub)
resource "aws_cloudwatch_event_rule" "securityhub_findings_rule" {
  count       = var.enable_security_hub ? 1 : 0
  name        = "${var.project_name}-securityhub-findings"
  description = "Captures AWS Security Hub FAILED compliance findings and routes to Risk Register Lambda"

  event_pattern = jsonencode({
    source      = ["aws.securityhub"]
    detail-type = ["Security Hub Findings - Imported"]
    detail = {
      findings = {
        Compliance = {
          Status = ["FAILED"]
        }
      }
    }
  })
}

resource "aws_cloudwatch_event_target" "securityhub_lambda_target" {
  count     = var.enable_security_hub ? 1 : 0
  rule      = aws_cloudwatch_event_rule.securityhub_findings_rule[0].name
  target_id = "TriggerRiskRegisterLambdaSecurityHub"
  arn       = aws_lambda_function.risk_register_logger.arn
}

resource "aws_lambda_permission" "allow_eventbridge_securityhub" {
  count         = var.enable_security_hub ? 1 : 0
  statement_id  = "AllowExecutionFromEventBridgeSecurityHub"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.risk_register_logger.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.securityhub_findings_rule[0].arn
}

# EventBridge Rule B: AWS Config NON_COMPLIANT Evaluations
resource "aws_cloudwatch_event_rule" "config_compliance_rule" {
  name        = "${var.project_name}-config-compliance"
  description = "Captures AWS Config NON_COMPLIANT rule evaluations and routes to Risk Register Lambda"

  event_pattern = jsonencode({
    source      = ["aws.config"]
    detail-type = ["Config Rules Compliance Change"]
    detail = {
      newEvaluationResult = {
        complianceType = ["NON_COMPLIANT"]
      }
    }
  })
}

resource "aws_cloudwatch_event_target" "config_lambda_target" {
  rule      = aws_cloudwatch_event_rule.config_compliance_rule.name
  target_id = "TriggerRiskRegisterLambdaConfig"
  arn       = aws_lambda_function.risk_register_logger.arn
}

resource "aws_lambda_permission" "allow_eventbridge_config" {
  statement_id  = "AllowExecutionFromEventBridgeConfig"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.risk_register_logger.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.config_compliance_rule.arn
}
