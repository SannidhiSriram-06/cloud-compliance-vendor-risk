# Product Requirements Document (PRD)

## Project Name: Cloud Compliance & Vendor Risk Governance Framework
**Repository:** `cloud-compliance-vendor-risk`  
**Document Version:** 1.0.0  
**Status:** Prototype Baseline  
**Author:** Sannidhi Sriram  

---

## 1. Executive Summary & Context of Existence
Modern enterprises operating in public cloud environments face two intertwined governance challenges:
1. **Continuous Cloud Compliance Drift:** Cloud engineering velocity frequently leads to configuration drift against regulatory baselines (e.g., CIS AWS Foundations Benchmark, ISO/IEC 27001, NIST CSF), leaving cloud infrastructure vulnerable to data leakage and credential exploitation.
2. **Disconnected Third-Party Risk Management (TPRM):** Organizations rely heavily on external SaaS and cloud vendors, but vendor risk assessments are often conducted through static, manual spreadsheets disconnected from technical cloud governance baselines.

### Advisory & Professional Context: Why This Project Exists
This project is built specifically as a hands-on technical demonstration for enterprise cyber advisory roles: GRC platform engineering and third-party risk:
- **Cyber Platforms & Engineering:** Implements and integrates enterprise GRC platforms (ServiceNow, Archer, Workiva, MetricStream, OneTrust) across the complete solution lifecycle (design, configuration, integration, reporting, and optimization) for clients managing regulatory compliance, IT General Controls (ITGC), and third-party risk.
- **Third-Party Risk Management (TPRM):** Executes vendor risk assessments, due diligence reviews, third-party questionnaires, and ongoing risk register maintenance.

Because replicating a licensed commercial enterprise GRC platform (such as ServiceNow GRC or Archer) is impossible on a self-funded budget, this project implements a lightweight open-source/hand-rolled GRC tool via Docker Compose and serverless automation. **This is explicitly an open-source substitute to prove foundational GRC engineering competencies—detecting misconfigurations, enriching findings with control framework crosswalks, and executing structured vendor intake workflows—rather than claiming direct platform-specific ServiceNow or Archer administrative experience.**

---

## 2. Target Audience & Operational Boundaries
- **Primary Persona:** An aspiring Cloud Compliance & GRC Consultant / Associate demonstrating core technical capabilities mapped directly to enterprise cyber advisory functions.
- **Evaluation Stakeholders:** Cyber Strategy and Technology leaders, practice directors, and cloud security architects assessing:
  - Infrastructure as Code (IaC) governance via Terraform.
  - Automated detection and baseline evaluation using native AWS security services (AWS Config, AWS Security Hub).
  - Cross-framework compliance mapping (CIS Benchmark, ISO 27001:2022 Annex A, NIST CSF v1.1).
  - Third-Party Vendor Risk intake, weighted scoring, residual risk tiering, and executive reporting.
- **Controlled Misconfiguration Notice:** The four non-compliant resources (public S3, unrestricted SSH, unencrypted EBS, IAM user without MFA) are provisioned deliberately in an isolated sandbox solely to generate authentic findings for detection. This is explicitly not a production architecture pattern.

---

## 3. Goals & Objectives
- **G-1 (Automated Auditing):** Provision AWS Config and AWS Security Hub to automatically audit AWS sandbox resources against the CIS AWS Foundations Benchmark v1.4.0.
- **G-2 (Controlled Vulnerability Demo):** Deploy four deliberate, isolated misconfigurations in a sandbox environment to demonstrate real-world detection:
  - S3 bucket with public read permissions.
  - Security group with port 22 open to `0.0.0.0/0`.
  - Unencrypted Amazon EBS volume.
  - IAM user with console credentials but no Multi-Factor Authentication (MFA).
- **G-3 (Serverless Risk Pipeline):** Implement an event-driven serverless pipeline using Amazon EventBridge and AWS Lambda to ingest non-compliant findings, calculate standardized risk scores and remediation SLAs, and persist records to an automated S3 Risk Register (JSON and CSV).
- **G-4 (Compliance Crosswalk):** Automatically enrich each cloud finding with bidirectional mappings to ISO/IEC 27001:2022 Annex A and NIST CSF v1.1 control identifiers.
- **G-5 (Vendor Risk Intake Engine):** Deliver a structured Third-Party Risk Assessment framework featuring a 14-question weighted intake questionnaire, a Python scoring CLI, and a self-hosted lightweight GRC dashboard.

---

## 4. Non-Goals
- **NG-1 (Automated Remediation):** This system does not execute automated auto-remediation (e.g., modifying security group ingress rules or locking S3 buckets automatically) to prevent accidental disruption during assessment reviews.
- **NG-2 (Enterprise Ticketing Integration):** Integration with commercial proprietary ticketing platforms (ServiceNow, Jira Service Desk, Archer) is out of scope.
- **NG-3 (Multi-Cloud Support):** Support for Microsoft Azure and Google Cloud Platform is excluded from this release; the implementation exclusively focuses on Amazon Web Services (AWS).
- **NG-4 (Production Scale & Multi-Region):** The system does not target high availability (HA) or multi-region data aggregation; it is designed strictly for demonstration and portfolio assessment within a single sandbox region (`us-east-1`).

---

## 5. Success Criteria ("Definition of Done")
The demo is considered complete and successfully validated when:
1. `terraform apply` deploys AWS Config, AWS Security Hub (CIS v1.4.0), the 4 vulnerable test resources, the EventBridge rule, and the processor Lambda without errors.
2. Non-compliant configurations are flagged by AWS Config and Security Hub within their evaluation windows.
3. EventBridge triggers `risk_register_processor.py`, generating and updating `risk_register.json` and `risk_register.csv` in the designated S3 bucket.
4. Each recorded finding in the risk register contains valid control IDs for ISO 27001:2022, NIST CSF, and CIS AWS Benchmark, along with SLA targets.
5. The TPRM engine (`vendor_risk_assessment.py`) processes the intake questionnaire, calculates category compliance percentages, assigns residual risk tiers, and outputs an executive markdown report and JSON summary.
6. The self-hosted Docker GRC dashboard launches locally on port 8080 and displays both the cloud risk register and third-party vendor assessment.
7. `terraform destroy` successfully removes all created cloud assets without orphaned resources.

---

## 6. Scope Boundaries & Constraints
- **Budget Constraint:** Total deployment cost must remain within AWS free-tier and standard trial allowances (under $1.00 USD for a typical testing cycle).
- **Environment:** Dedicated sandbox or developer playground account; deployment into enterprise production accounts is strictly prohibited.
- **Tooling Footprint:** Limited to standard cloud engineering tools: Terraform (>= 1.5.0), Python (>= 3.10), Docker, and AWS CLI v2.
