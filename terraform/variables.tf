variable "aws_region" {
  description = "The AWS region to deploy compliance monitoring and demo resources"
  type        = string
  default     = "us-east-1"
}

variable "enable_security_hub" {
  description = "Whether to enable AWS Security Hub and its standards subscriptions"
  type        = bool
  default     = true
}

variable "project_name" {
  description = "Prefix name for resources"
  type        = string
  default     = "cloud-compliance-demo"
}

variable "environment" {
  description = "Deployment environment name"
  type        = string
  default     = "sandbox"
}

variable "enable_vulnerable_demo_resources" {
  description = "Whether to deploy deliberately misconfigured resources for demo evaluation"
  type        = bool
  default     = true
}

variable "cis_benchmark_version" {
  description = "CIS AWS Foundations Benchmark version for Security Hub"
  type        = string
  default     = "1.4.0"
}
