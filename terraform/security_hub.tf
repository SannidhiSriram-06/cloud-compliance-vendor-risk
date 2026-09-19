# Enable AWS Security Hub
resource "aws_securityhub_account" "main" {
  enable_default_standards = false
  auto_enable_controls     = true
}

# Subscribe to CIS AWS Foundations Benchmark
resource "aws_securityhub_standards_subscription" "cis_aws_foundations_benchmark" {
  standards_arn = "arn:aws:securityhub:${var.aws_region}::standards/cis-aws-foundations-benchmark/v/${var.cis_benchmark_version}"
  depends_on    = [aws_securityhub_account.main]
}

# Subscribe to AWS Foundational Security Best Practices (FSBP)
resource "aws_securityhub_standards_subscription" "aws_foundational_security_best_practices" {
  standards_arn = "arn:aws:securityhub:${var.aws_region}::standards/aws-foundational-security-best-practices/v/1.0.0"
  depends_on    = [aws_securityhub_account.main]
}
