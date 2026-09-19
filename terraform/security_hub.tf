# Enable AWS Security Hub
resource "aws_securityhub_account" "main" {
  count                    = var.enable_security_hub ? 1 : 0
  enable_default_standards = false
  auto_enable_controls     = true
}

# Subscribe to CIS AWS Foundations Benchmark
resource "aws_securityhub_standards_subscription" "cis_aws_foundations_benchmark" {
  count         = var.enable_security_hub ? 1 : 0
  standards_arn = "arn:aws:securityhub:${var.aws_region}::standards/cis-aws-foundations-benchmark/v/${var.cis_benchmark_version}"
  depends_on    = [aws_securityhub_account.main]
}

