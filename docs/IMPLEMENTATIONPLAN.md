# Implementation & Execution Roadmap

## Project Name: Cloud Compliance & Vendor Risk Governance Framework
**Repository:** `cloud-compliance-vendor-risk`  
**Execution Context:** Engineering Roadmap & Architectural Delivery  

---

## 1. Plan Overview & Chronological Strategy

The implementation was sequenced logically from foundational infrastructure and core compliance services through detection testing, automated ingestion, vendor risk workflow development, and executive documentation.

```
[ Phase 1: Foundation ] ──► [ Phase 2: Vulnerabilities ] ──► [ Phase 3: Serverless Ingestion ] ──► [ Phase 4: TPRM ] ──► [ Phase 5: GRC UI ] ──► [ Phase 6: Docs ]
```

---

## 2. Phase-by-Phase Build Breakdown

### Phase 1: Base Infrastructure & Compliance Scanners
- **Objective:** Provision baseline AWS environment, secure storage, and activate compliance evaluation engines.
- **Tasks Completed:**
  - Define Terraform AWS provider requirements (`terraform/provider.tf`, `variables.tf`).
  - Configure private S3 bucket for AWS Config snapshots with AES-256 encryption.
  - Authorize AWS Config IAM role and attach `AWS_ConfigRole`.
  - Initialize AWS Config recorder, delivery channel, and recorder status.
  - Deploy managed AWS Config rules: `s3-bucket-public-read-prohibited`, `restricted-ssh`, `encrypted-volumes`, `iam-user-mfa-enabled`.
  - Enable AWS Security Hub and subscribe strictly to the CIS AWS Foundations Benchmark v1.4.0 standard.
- **Deliverables:** `provider.tf`, `variables.tf`, `config.tf`, `security_hub.tf`.

---

### Phase 2: Deliberate Sandbox Misconfigurations
- **Objective:** Provision isolated, non-compliant resources to validate audit triggers.
- **Tasks Completed:**
  - Provision S3 bucket with public access block disabled and wildcard read policy.
  - Provision EC2 Security Group allowing unrestricted port 22 inbound traffic (`0.0.0.0/0`).
  - Provision attached EBS volume (`gp3`, 1 GiB) with encryption explicitly disabled, attached to a `t3.nano` Amazon Linux 2023 EC2 instance.
  - Provision IAM test user with console login profile but without MFA enforcement.
  - Tag all resources with `ComplianceFinding` and `DemoResource` metadata.
- **Deliverables:** `vulnerable_resources.tf`.

---

### Phase 3: Serverless Ingestion & Compliance Mapping Pipeline
- **Objective:** Implement automated event routing and crosswalk enrichment into an S3 risk register.
- **Tasks Completed:**
  - Build `COMPLIANCE_MAPPINGS` dictionary crosswalk between CIS Benchmark v1.4.0, ISO/IEC 27001:2022, and NIST CSF v1.1.
  - Implement Python Lambda handler `risk_register_processor.py` to parse ASFF and Config compliance payloads.
  - Deploy two EventBridge rules: Security Hub FAILED findings and Config NON_COMPLIANT evaluations. Ignore `securityhub-*` Config rule duplicates.
  - Write individual finding objects under `findings/<hash>.json` and dynamically rebuild consolidated `risk_register.json` and `risk_register.csv`.
  - Implement deduplication by `(control, resource)` merging sources into a `Sources` list.
- **Deliverables:** `eventbridge_lambda.tf`, `lambda/risk_register_processor.py`, `lambda/test_processor.py`, `outputs.tf`.

---

### Phase 4: Third-Party Vendor Risk Assessment (TPRM) Module
- **Objective:** Build an enterprise vendor risk evaluation and intake framework.
- **Tasks Completed:**
  - Construct 14-question intake questionnaire with category weights and standard references (`vendor_intake_questionnaire.csv`).
  - Develop Python scoring engine `vendor_risk_assessment.py` supporting CLI flags.
  - Implement scoring algorithms computing domain percentages, identifying deficiencies, and assigning residual risk tiers (`LOW`, `MEDIUM`, `HIGH`).
  - Implement automatic generation of executive markdown report (`sample_vendor_report.md`) and JSON summary (`sample_vendor_assessment.json`), explicitly documenting that assessments evaluate a fictional vendor with simulated responses for demonstration purposes.
- **Deliverables:** `vendor_intake_questionnaire.csv`, `vendor_risk_assessment.py`, `sample_vendor_assessment.json`, `sample_vendor_report.md`.

---

### Phase 5: Self-Hosted GRC Portal & Local Dashboard
- **Objective:** Deliver a self-hosted visual presentation layer for compliance findings.
- **Tasks Completed:**
  - Create Flask application (`grc/app/app.py`) exposing REST endpoints for risk register and vendor data.
  - Design responsive HTML dashboard (`grc/app/templates/index.html`) displaying metrics cards, finding tables with control tags, and vendor scorecards.
  - Package application into Docker Compose specification (`grc/docker-compose.yml`) mounting data volumes.
  - Display prototype disclaimer clarifying it is a lightweight demonstration dashboard and not an official or commercial GRC product.
- **Deliverables:** `grc/docker-compose.yml`, `grc/app/app.py`, `grc/app/templates/index.html`.

---

### Phase 6: Advisory Documentation & Validation
- **Objective:** Author comprehensive technical, architecture, and regulatory documentation.
- **Tasks Completed:**
  - Author detailed crosswalk matrix and provenance glossary in `docs/COMPLIANCE_CONTROL_MAPPING.md`.
  - Compile enterprise `README.md` with Mermaid architecture diagram, step-by-step deploy instructions, cost analysis, and teardown procedures.
  - Perform clean validation run (`terraform validate`, unit test suite, offline live sample replay).
- **Deliverables:** `docs/COMPLIANCE_CONTROL_MAPPING.md`, `README.md`.
