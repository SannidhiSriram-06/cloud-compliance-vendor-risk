# End-to-End Operational Application Flow (APPFLOW)

## Project Name: Cloud Compliance & Vendor Risk Governance Framework
**Repository:** `cloud-compliance-vendor-risk`  
**Target Audience:** Security Engineers, Auditors, and Demonstration Reviewers  

---

## 1. Overview
This document describes the exact execution sequence of the automated compliance monitoring and vendor risk assessment platform, from infrastructure deployment through finding detection, enrichment, risk register updates, and vendor scoring.

```
[ Phase 1: Deploy ] ──► [ Phase 2: Detection ] ──► [ Phase 3: Ingestion ] ──► [ Phase 4: TPRM ] ──► [ Phase 5: Teardown ]
```

---

## 2. Step-by-Step Execution Sequence

### Phase 1: Infrastructure Provisioning & Initialization
1. **Operator Command:** The engineer navigates to `/terraform` and executes:
   ```bash
   terraform init && terraform apply -auto-approve
   ```
2. **Provider & S3 Initialization:**
   - Terraform sets up the AWS provider for `us-east-1`.
   - Two private S3 buckets are created:
     - Config Delivery Bucket: `${project_name}-config-<random_string>`
     - Risk Register Bucket: `${project_name}-risk-register-<random_string>`
   - Public access blocks and AES-256 server-side encryption are applied to both buckets.
3. **AWS Config & Security Hub Activation:**
   - AWS Config configuration recorder starts recording global and regional resource changes.
   - Delivery channel connects to the config delivery bucket.
   - Four managed Config rules are registered (`s3-bucket-public-read-prohibited`, `restricted-ssh`, `encrypted-volumes`, `iam-user-mfa-enabled`).
   - Security Hub account is initialized and subscribed to the CIS AWS Foundations Benchmark v1.4.0 standard.
4. **Deliberately Misconfigured Demo Resources Deployed:**
   - `aws_s3_bucket.public_demo_bucket`: Deployed with public read bucket policy allowing `s3:GetObject` to wildcard `*`.
   - `aws_security_group.open_ssh_sg`: Deployed with port 22 open to `0.0.0.0/0`.
   - `aws_ebs_volume.unencrypted_demo_volume`: Deployed with `encrypted = false`.
   - `aws_iam_user.no_mfa_demo_user`: Console credentials generated without an associated MFA virtual/hardware token.
5. **Serverless Ingestion Pipeline Deployed:**
   - Python code `lambda/risk_register_processor.py` is zipped.
   - IAM role and policy granting S3 read/write and CloudWatch logging permissions are attached to the Lambda.
   - Lambda function `${project_name}-risk-register-logger` is created.
   - CloudWatch EventBridge rule `${project_name}-compliance-evaluations` and invoke permission are configured.

---

### Phase 2: Compliance Scanning & Finding Generation
1. **AWS Config Recording:**
   - Config recorder detects configuration state changes across the newly provisioned resources.
   - Managed rules evaluate resource metadata against compliance logic:
     - The public S3 bucket fails `s3-bucket-public-read-prohibited`.
     - The open security group fails `restricted-ssh`.
     - The unencrypted EBS volume fails `encrypted-volumes`.
     - The test IAM user fails `iam-user-mfa-enabled`.
2. **Security Hub CIS Benchmark Evaluation:**
   - CIS controls (e.g., CIS 2.1.5, CIS 5.2, CIS 2.2.1, CIS 1.5) evaluate the resources.
   - Non-compliant resources trigger `FAILED` compliance statuses in AWS Security Finding Format (ASFF).
3. **Event Publication:**
   - AWS Config emits a `Config Rules Compliance Change` event to the default EventBridge bus.
   - AWS Security Hub emits a `Security Hub Findings - Imported` event to the default EventBridge bus.

---

### Phase 3: Serverless Ingestion & Risk Register Enrichment
1. **Event Interception:**
   - The EventBridge rule matches the event source (`aws.securityhub` or `aws.config`) and dispatches the payload to the Lambda function.
2. **Lambda Handler Processing (`risk_register_processor.py`):**
   - **Step 2.1:** Inspects the event source. If Security Hub, calls `parse_security_hub_finding()`; if Config, calls `parse_config_event()`.
   - **Step 2.2:** Filters for items with compliance status `FAILED`, `WARNING`, or `NON_COMPLIANT`.
   - **Step 2.3:** Extracts finding title, description, resource ARN, and severity.
   - **Step 2.4:** Calls `find_control_mapping()` against `COMPLIANCE_MAPPINGS`:
     - Identifies corresponding ISO 27001:2022 Annex A control (e.g., `A.5.15`, `A.8.24`, `A.8.20`).
     - Identifies NIST CSF control (e.g., `PR.AC-3`, `PR.DS-1`, `PR.PT-4`).
     - Identifies CIS benchmark rule ID (e.g., `2.1.5`, `5.2`).
     - Assigns specific remediation guidance.
   - **Step 2.5:** Computes remediation SLA target days (`CRITICAL`: 1 day, `HIGH`: 7 days, `MEDIUM`: 30 days, `LOW`: 90 days).
3. **S3 Register Persistence:**
   - Lambda checks for an existing `risk_register.json` in the S3 bucket.
   - Deduplicates or updates records based on unique `FindingID`.
   - Commits updated `risk_register.json`.
   - Formats records into standard comma-separated values and commits `risk_register.csv`.

---

### Phase 4: Third-Party Risk Assessment (TPRM) Execution
1. **Vendor Intake Execution:**
   - Security consultant runs the assessment CLI:
     ```bash
     cd vendor-risk
     python3 vendor_risk_assessment.py --vendor "Apex Cloud Analytics Inc."
     ```
2. **Scoring Engine Operations:**
   - Loads 14 controls from `vendor_intake_questionnaire.csv`.
   - Reads vendor responses (`YES`, `PARTIAL`, `NO`).
   - Calculates domain scores across 6 categories (Data Protection, Access & Identity, Incident Response, Cloud Operations, Compliance & Governance, Resilience & DR).
   - Flags critical deficiencies (e.g., missing quarterly access reviews, lack of automated CIS benchmark scanning).
   - Computes weighted overall compliance percentage and assigns residual risk tier (`LOW`, `MEDIUM`, `HIGH`).
3. **Artifact Output:**
   - Outputs machine-readable `sample_vendor_assessment.json`.
   - Compiles formal markdown executive report `sample_vendor_report.md`.
4. **Local Dashboard Presentation (Optional):**
   - User executes `docker compose up -d` in `/grc`.
   - Web application starts on `http://localhost:8080`.
   - Pulls data from `live_risk_register_sample.json` and `sample_vendor_assessment.json`.
   - Renders active cloud findings alongside third-party vendor risk scores.

---

### Phase 5: Resource Teardown
1. **Operator Teardown Command:**
   ```bash
   cd terraform
   terraform destroy -auto-approve
   ```
2. **Cleanup Confirmation:**
   - All S3 buckets, Config recorders, Security Hub subscriptions, IAM roles, and vulnerable sandbox assets are deleted cleanly.
