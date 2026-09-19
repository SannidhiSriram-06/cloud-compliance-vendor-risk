# System Design Rationale & Architectural Decisions

## Project Name: Cloud Compliance & Vendor Risk Governance Framework
**Repository:** `cloud-compliance-vendor-risk`  
**Engagement Type:** Portfolio-Grade Security Architecture & Governance Lab  
**Practice Area:** Cloud Security, GRC Advisory, & Infrastructure Engineering  

---

## 1. Executive Context & Architectural Philosophy

Enterprise governance, risk, and compliance frameworks require a clear bridge between technical cloud security postures and formal audit controls. When architecting this solution, the primary design objective was to build a verifiable, reproducible technical pipeline that translates raw infrastructure misconfigurations directly into governance frameworks (specifically CIS AWS Foundations Benchmark, ISO/IEC 27001, and NIST CSF).

This document outlines the architectural rationale, evaluated trade-offs, and design decisions underpinning the repository.

---

## 2. Architecture Decisions & Alternatives Evaluated

### 2.1 Native AWS Config & Security Hub vs. Third-Party CSPM (e.g., Wiz, Prisma Cloud)
- **Decision:** Implement native AWS Config and AWS Security Hub rather than third-party Cloud Security Posture Management (CSPM) software.
- **Rationale:**
  - Standard AWS native services require zero external agent installation or API key sharing with external SaaS providers.
  - AWS Security Hub provides an authoritative implementation of the CIS AWS Foundations Benchmark (v1.4.0) that maps directly to AWS Security Finding Format (ASFF).
  - AWS Config offers continuous state recording with granular event emissions upon resource state changes.
- **Alternatives Rejected:**
  - *Third-Party CSPM Platforms (Wiz / Palo Alto Prisma Cloud / Orca):* Commercial platforms require expensive enterprise licensing, complex vendor onboarding, and external infrastructure connections that make open-source reproducibility and portfolio review infeasible.
  - *Custom Periodic Python Polling Scripts:* Writing custom Boto3 scanners running on cron triggers creates maintenance debt, lacks native continuous change detection, and requires bespoke logic for hundreds of resource types.

---

### 2.2 Event-Driven Serverless Pipeline vs. Scheduled Batch Aggregation
- **Decision:** Utilize Amazon EventBridge combined with an AWS Lambda function triggered on compliance change events.
- **Rationale:**
  - Event-driven processing achieves near real-time ingestion latency (seconds rather than hours).
  - AWS Lambda scales to zero, incurring zero compute cost when no infrastructure changes occur.
  - Event filtering at the EventBridge bus level eliminates unnecessary Lambda invocations for compliant or informational events.
- **Alternatives Rejected:**
  - *Scheduled Batch Lambda (e.g., Daily Cron):* Introduces an unacceptable evaluation lag where an insecure asset (such as an open SSH port) could exist for up to 24 hours before entering the risk register.
  - *Persistent Polling Worker (EC2 / Container):* Maintaining a container or virtual machine continuously polling the AWS Security Hub API introduces unnecessary operational complexity, patching overhead, and continuous EC2 hourly billing.

---

### 2.3 S3-Backed Automated Risk Register & Open-Source Dashboard vs. Enterprise GRC Platforms
- **Decision:** Store the dynamic risk register directly in Amazon S3 as dual JSON and CSV artifacts, paired with a lightweight, containerized open-source visualization dashboard (`grc/`).
- **Consulting Rationale & Open-Source Substitution:**
  - In enterprise advisory (such as enterprise cyber advisory roles: GRC platform engineering and third-party risk), consultants architect and integrate commercial GRC systems (ServiceNow GRC, Archer, Workiva, MetricStream, OneTrust) across full implementation lifecycles.
  - On a personal sandbox and self-funded budget, commercial GRC software licenses are unobtainable. This project explicitly deploys a lightweight, hand-rolled open-source GRC substitute (Flask/Docker) paired with S3 storage.
  - This architecture proves the core underlying competencies—detecting misconfigurations, enriching findings with control framework crosswalks (ISO 27001 / NIST CSF), and maintaining risk registers—without falsely claiming platform-specific ServiceNow or Archer administrative experience.
  - Generates both machine-readable JSON (for automated pipelines) and auditor-friendly CSV (for management reporting and spreadsheet due-diligence).
- **Alternatives Rejected:**
  - *ServiceNow GRC / Archer / MetricStream:* Enterprise GRC systems carry multi-thousand-dollar licensing costs and multi-week provisioning cycles that cannot be bundled into a public, reproducible demonstration repository.
  - *Relational Database (Amazon RDS / PostgreSQL):* Deploying an RDS instance incurs continuous hourly infrastructure charges (typically ~$15–$30/month minimum for db.t3.micro) and requires VPC subnet group overhead for a dataset that fits cleanly in document storage.

---

### 2.4 Separation of Technical Cloud Compliance and Third-Party Vendor Risk (TPRM)
- **Decision:** Implement a dual-track architecture containing both an automated cloud configuration auditor and a structured questionnaire-driven vendor risk assessment engine.
- **Rationale:**
  - In enterprise advisory and audit environments, organizations do not evaluate their internal infrastructure in a vacuum; third-party vendor relationships frequently represent the primary vector for data breaches.
  - Demonstrates holistic risk management by connecting technical infrastructure control assessments (ISO 27001 A.8) directly to vendor governance (ISO 27001 A.5.19 / A.5.20).
- **Alternatives Rejected:**
  - *Focusing Solely on Cloud Scanning:* Demonstrates technical cloud security but fails to reflect broader GRC and consulting competencies such as vendor due diligence, contract SLA evaluation, and risk tiering.

---

## 3. Engineering Trade-offs: Prototype / Weekend Scope vs. Production Implementation

| Dimension | Portfolio Demo Implementation | Enterprise Production Target | Rationale for Trade-Off |
| :--- | :--- | :--- | :--- |
| **Regional Scope** | Single region (`us-east-1`) | Multi-region with AWS Config Aggregator | Minimizes AWS Config recording charges while fully proving the architectural pattern. |
| **Data Concurrency** | S3 object overwrite (read-modify-write in Lambda) | Amazon DynamoDB with conditional writes / Amazon Aurora Serverless | For demonstration volumes (< 100 findings), concurrent race conditions are negligible; avoids database provisioning costs. |
| **Identity Integration** | AWS IAM Access Keys and standard roles | Single Sign-On (AWS IAM Identity Center) with SAML 2.0 / Okta | Eliminates external enterprise directory prerequisites for reviewers replicating the lab. |
| **Remediation Action** | Detective and advisory only (generates risk entries and SLA recommendations) | Automated active remediation (AWS Systems Manager Automation documents) | Automated modification of resources can mask security states during live evaluation and create unintended operational disruption. |
| **Vendor Intake Workflow** | Python CLI processing structured CSV templates | Dedicated web portal with role-based vendor self-service submission | Avoids complex multi-tenant user authentication and database backends for the intake exercise. |

---

## 4. Architectural Summary
The resulting architecture balances fidelity to enterprise standards with operational economy. It demonstrates production-level infrastructure design, compliance cross-referencing, and risk quantification within a low-cost, reproducible sandbox.
