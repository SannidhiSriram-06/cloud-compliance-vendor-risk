# Operational Rules & Security Hygiene (RULES)

## Project Name: Cloud Compliance & Vendor Risk Governance Framework
**Repository:** `cloud-compliance-vendor-risk`  
**Classification:** Operational Safety Standard Operating Procedure  

---

## 1. Portfolio & Demonstration Notice
> **IMPORTANT NOTICE:**  
> This project is designed strictly as an educational demonstration and portfolio-grade governance laboratory. It is **NOT** a hardened production system. The resources created in `terraform/vulnerable_resources.tf` (such as public S3 buckets and open ingress security groups) are deliberately configured with insecure postures for audit evaluation purposes.  
> **Under no circumstances should this code be deployed into an enterprise production AWS account or any environment storing sensitive or regulated data.**

---

## 2. Cloud Cost Controls & Financial Governance

1. **Leverage Free Tiers and Trial Quotas:**
   - AWS Security Hub provides a 30-day free trial upon initial enablement.
   - AWS Config charges per configuration item recorded (~$0.003 per item) and per rule evaluation ($0.001 per evaluation).
   - AWS Lambda provides 1,000,000 free requests per month under the Always Free tier.
2. **Set AWS CloudWatch Billing Alerts:**
   - Configure a CloudWatch billing alarm at the $5.00 and $10.00 USD thresholds prior to running Terraform.
3. **Mandatory Teardown After Demonstration Sessions:**
   - Immediately upon completing demonstration runs, testing, or screenshot capture, execute:
     ```bash
     cd terraform
     terraform destroy -auto-approve
     ```
   - Confirm via the AWS Management Console that AWS Config recording is disabled and all demo S3 buckets have been deleted to prevent recurring charges.

---

## 3. Security Hygiene & Credential Protection

1. **Strict Prohibition on Secret Commits:**
   - Never commit AWS access keys, secret keys, session tokens, or local credentials to Git.
   - Maintain active `.gitignore` rules covering:
     - `*.tfstate` and `*.tfstate.*` (contains plaintext outputs and resource attributes).
     - `*.tfvars` (contains environment-specific variables).
     - Local virtual environments (`.venv/`, `env/`).
     - Output files (`risk_register_export.csv`, generated reports).
2. **Network Perimeter Restraints:**
   - Even in sandbox environments, never open administrative ports to `0.0.0.0/0` outside of the isolated demo resource.
   - If deploying real workloads, restrict security group ingress CIDRs strictly to your workstation IP (`<your-ip>/32`).
3. **IAM Least Privilege:**
   - The Terraform execution identity should have scoped permissions for Config, Security Hub, S3, and Lambda, rather than unrestricted root account access.
   - The Lambda function's IAM role must never receive `AdministratorAccess` or wildcard `*` write privileges across the AWS account.

---

## 4. Sandbox Isolation Guidelines
- Run this laboratory in an isolated AWS sandbox account or dedicated AWS Organizations Organizational Unit (OU) with Service Control Policies (SCPs) preventing cross-account resource peering.
- Do not store real customer data, real vendor contracts, or real company intellectual property in the vendor assessment templates or S3 buckets.
