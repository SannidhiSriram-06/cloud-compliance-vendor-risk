# Technical Specification (TECHSPEC)

## Project Name: Cloud Compliance & Vendor Risk Governance Framework
**Repository:** `cloud-compliance-vendor-risk`  
**Document Version:** 1.0.0  
**Classification:** Technical Architecture & Design Document  

---

## 1. System Architecture Overview

The framework operates on an event-driven serverless architecture on AWS, coupled with an off-cloud local Third-Party Risk Management (TPRM) analysis and visualization tier.

```
[ Misconfigured Sandbox Resources ]
  - S3 Public Bucket
  - SG 0.0.0.0/0:22
  - Unencrypted EBS
  - IAM User without MFA
            │
            ▼
[ AWS Compliance Scanners ]
  - AWS Config (Managed Rules)
  - AWS Security Hub (CIS AWS Benchmark v1.4.0)
            │
            ▼
[ Amazon EventBridge ]
  (Rule: detail-type: "Security Hub Findings - Imported" & "Config Rules Compliance Change")
            │
            ▼
[ AWS Lambda (Python 3.11) ]
  - Finding Ingestion & Deduplication
  - Control Mapping Engine (ISO 27001 / NIST CSF / CIS)
  - SLA & Risk Score Calculation
            │
            ▼
[ Amazon S3 Risk Register Bucket ]
  - risk_register.json
  - risk_register.csv
            │
            ▼ (Read-Only Volume / API Sync)
[ Local GRC Web Portal (Docker / Flask) ]
  - Cloud Risk Register Viewer
  - TPRM Vendor Scorecard & Gap Analysis
```

---

## 2. Component Breakdown & Selection Rationale

### 2.1 AWS Config
- **Function:** Continuous resource configuration tracking and compliance evaluation.
- **Rules Configured:**
  - `s3-bucket-public-read-prohibited`: Evaluates S3 bucket ACLs and policies against public access permissions.
  - `restricted-ssh`: Detects security group ingress rules specifying port 22 and `0.0.0.0/0`.
  - `encrypted-volumes`: Verifies if attached or detached Amazon EBS volumes have KMS encryption enabled.
  - `iam-user-mfa-enabled`: Identifies console-enabled IAM user accounts missing active virtual or hardware MFA tokens.
- **Rationale:** AWS Config provides continuous configuration recording and native change notifications, acting as the authoritative configuration baseline.

### 2.2 AWS Security Hub
- **Function:** Centralized cloud security posture management (CSPM) aggregating findings in AWS Security Finding Format (ASFF).
- **Standards Subscribed:**
  - `CIS AWS Foundations Benchmark v1.4.0` (`arn:aws:securityhub:<region>::standards/cis-aws-foundations-benchmark/v/1.4.0`).
  - `AWS Foundational Security Best Practices v1.0.0`.
- **Rationale:** Security Hub provides regulatory-aligned evaluations out of the box, translating technical resource states into compliance audit checks.

### 2.3 Amazon EventBridge
- **Function:** Event bus routing compliance failure events to execution handlers.
- **Event Pattern:**
  ```json
  {
    "source": ["aws.securityhub", "aws.config"],
    "detail-type": [
      "Security Hub Findings - Imported",
      "Config Rules Compliance Change"
    ]
  }
  ```
- **Rationale:** Serverless, push-based delivery avoids costly polling intervals and reduces execution latency to sub-second timeframes.

### 2.4 AWS Lambda (Risk Register Processor)
- **Runtime:** Python 3.11.
- **Function:** Parses ASFF findings and AWS Config evaluations, matches rule IDs against the compliance crosswalk dictionary, computes SLA windows, and writes back consolidated `risk_register.json` and `risk_register.csv` files to S3.
- **Package:** Automated zip generation via Terraform `archive_file` data source.
- **Execution Role Policies:** Least-privilege access restricted to S3 object read/write on the designated risk register bucket and CloudWatch Logs creation.

### 2.5 TPRM Assessment Engine (`vendor_risk_assessment.py`)
- **Technology:** Python 3 standard library (`csv`, `json`, `argparse`).
- **Function:** Reads intake questionnaire data, computes weighted scores across six operational domains, identifies control gaps, and outputs markdown executive summaries and machine-readable JSON assessments.

### 2.6 Local Open-Source GRC Dashboard (`grc/`)
- **Technology:** Python 3.11-slim, Flask 2.3+, Bootstrap 5.3 (Dark Theme).
- **Packaging:** Docker Compose multi-stage container mounting local data directories.
- **Role as an Open-Source Substitute:** In enterprise consulting (e.g., enterprise cyber advisory roles: GRC platform engineering and third-party risk), clients deploy commercial GRC suites such as ServiceNow GRC, Archer, Workiva, or MetricStream. In this demonstration, this containerized web application serves explicitly as a lightweight open-source substitute to model the exact same functional ingestion, risk registry view, and vendor scorecard workflow without claiming commercial platform certification.

---

## 3. Data Flow Specification

1. **Detection Phase:**
   - Misconfigured resources are provisioned via `terraform/vulnerable_resources.tf`.
   - AWS Config and Security Hub evaluate resource states periodically and upon configuration changes.
2. **Event Dispatch:**
   - AWS Config generates a `Config Rules Compliance Change` event with `complianceType: NON_COMPLIANT`.
   - AWS Security Hub publishes a `Security Hub Findings - Imported` event with `Compliance.Status: FAILED`.
   - EventBridge intercepts matching events and triggers the Lambda function ARN.
3. **Enrichment & Transformation:**
   - Lambda extracts resource ID, rule name, finding severity, and description.
   - Lambda queries internal mapping dictionary `COMPLIANCE_MAPPINGS` to append ISO 27001:2022, ISO 27001:2013, and NIST CSF v1.1 identifiers.
   - Remediation SLA is assigned based on the `SLA_MATRIX` (`CRITICAL`: 1 day, `HIGH`: 7 days, `MEDIUM`: 30 days, `LOW`: 90 days).
4. **Persistence:**
   - Lambda retrieves existing `risk_register.json` from S3 (if present), merges current findings by unique `FindingID`, sorts records by `RiskScore` descending, and commits both JSON and CSV files back to S3.
5. **Consumption:**
   - The GRC dashboard or auditor reads the exported risk register and renders compliance posture metrics.

---

## 4. Key Configuration Decisions & Parameters

| Parameter / Resource | Chosen Setting | Rationale |
| :--- | :--- | :--- |
| **AWS Region** | `us-east-1` | Broadest service availability, lowest baseline latency, and standard CIS benchmark support. |
| **CIS Benchmark Version** | `1.4.0` | Standard enterprise baseline widely accepted in cloud security advisory assessments. |
| **S3 Storage Strategy** | S3 bucket with `force_destroy = true` | Simplifies clean resource teardown during evaluation without manual object emptying. |
| **Lambda Timeout** | 60 seconds | Sufficient buffer for S3 GET, JSON merge, and PUT operations without risking timeout errors. |
| **Risk Scoring Model** | Scale 1–10 (Critical=10, High=8, Medium=5, Low=2) | Aligns with standard CVSS / Qualitative enterprise audit rating scales. |

---

## 5. Known Limitations & Technical Debt

- **Single-Region Scope:** Config and Security Hub are enabled solely in the primary deployment region. Multi-region aggregator recorders are omitted to minimize billing charges.
- **Evaluation Latency:** AWS Config rule evaluations can require between 3 and 15 minutes to register compliance state changes following resource creation.
- **Stateless Register Storage:** Storing the risk register as a flat JSON/CSV file in S3 is suitable for demonstrations (< 1,000 findings) but lacks transactional concurrency controls (optimistic locking) present in relational databases or DynamoDB.
- **Sandbox Misconfigurations:** Test vulnerabilities (open SSH, public S3) are intentional and must strictly remain quarantined within sandbox accounts.
