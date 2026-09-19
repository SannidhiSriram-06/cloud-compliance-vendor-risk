# Cloud Compliance & GRC Framework Control Mapping

This document provides cross-framework control mappings between AWS Security Hub / AWS Config findings, the **CIS AWS Foundations Benchmark v1.4.0**, **ISO/IEC 27001:2022 (Annex A)**, and the **NIST Cybersecurity Framework (CSF v2.0 / v1.1)**.

---

## 0. Register Column Glossary & Provenance

To maintain audit integrity and avoid overclaiming compliance coverage, risk register columns are partitioned into **AWS-Sourced Telemetry** (ground truth from live scanners) and **Analyst-Assigned Classifications** (indicative crosswalks and governance metadata):

| Column | Provenance / Authority | Description & Basis |
| :--- | :--- | :--- |
| `Severity` | **AWS-Sourced** | Directly ingested from AWS Config / Security Hub normalized severity (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFORMATIONAL`). |
| `ResourceID` | **AWS-Sourced** | Cloud identifier (IAM username, S3 bucket name, EBS volume ID, AWS Account ID) extracted directly from event payload. |
| `Sources` | **AWS-Sourced** | Live ingestion channels (`AWS Config`, `AWS Security Hub`, or both if merged). |
| `CIS_AWS_Benchmark` | **AWS-Sourced** | CIS control reference from Security Hub's `Compliance.RelatedRequirements` or Config rule specification. |
| `CIS_Match` | **Classification** | `"exact"` where the CIS control number was taken directly from Security Hub `Compliance.RelatedRequirements` or matching Config rule; `"closest"` where mapped by topic analogy. |
| `ISO_27001_2022` | **Analyst-Assigned** | Hand-built indicative crosswalk to ISO/IEC 27001:2022 Annex A control clauses. |
| `NIST_CSF` | **Analyst-Assigned** | Hand-built indicative crosswalk to NIST Cybersecurity Framework (CSF v1.1 / v2.0) subcategories. |
| `ISO_NIST_Basis` | **Classification** | Always `"analyst-assigned (indicative)"` to document that ISO/NIST columns represent a crosswalk rather than official AWS or ISO certifications. |
| `Owner` | **Analyst-Assigned** | Assigned operational remediation team (`Identity & Access Team`, `Data Protection Team`, `SecOps / Network Team`, `Cloud Infrastructure Team`). |
| `RemediationSLA_Days` | **Governance Policy** | Organizationally defined remediation timeline based on severity SLA matrix (Critical: 3d, High: 7d, Medium: 30d, Low: 90d). |
| `ControlMapping` | **Telemetry/Logic** | `"MAPPED"` if recognized and assigned cross-framework controls; `"UNMAPPED"` if telemetry lacked rule mappings. |

---

## 1. Compliance Crosswalk Matrix

| AWS Finding / Resource | CIS AWS v1.4.0 Control | ISO 27001:2022 Control | ISO 27001:2013 Control | NIST CSF Control | Threat & Risk Impact | Remediation Action |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **S3 Public Read Access** (`s3-bucket-public-read-prohibited`) | **2.1.5**: Ensure S3 Bucket Access is Restricted | **A.5.15**: Access Control<br>**A.8.24**: Use of Cryptography | **A.9.4.2**: Secure Log-on<br>**A.13.1.1**: Network Controls | **PR.AC-3**: Access Management<br>**PR.DS-1**: Data-at-Rest Protection | Unauthorized internet actors can dump confidential databases, PII, intellectual property, or backups. | Enforce AWS S3 Block Public Access at the account and bucket level. Remove `*` principal from bucket policies. |
| **Unrestricted SSH Ingress** (`restricted-ssh` / `0.0.0.0/0:22`) | **5.2**: Ensure no Security Groups allow ingress from `0.0.0.0/0` to port 22 | **A.8.20**: Network Security<br>**A.8.21**: Security of Network Services | **A.13.1.1**: Network Controls<br>**A.13.1.2**: Security of Network Services | **PR.AC-5**: Network Integrity<br>**PR.PT-4**: Network Protection | SSH brute-force attacks, remote password guessing, zero-day exploitation against OpenSSH daemon. | Restrict port 22 ingress to corporate VPN/bastion CIDRs, or eliminate port 22 entirely using AWS SSM Session Manager. |
| **Unencrypted EBS Volume** (`encrypted-volumes`) | **2.2.1**: Ensure EBS Volume Encryption is Enabled in all regions | **A.8.24**: Use of Cryptography | **A.10.1.1**: Cryptographic Controls Policy | **PR.DS-1**: Data-at-Rest Protection | Plaintext volume exposure if snapshots are shared, stolen physical media, or non-compliant storage audits. | Enable default EBS encryption with KMS CMK or AWS-managed key. Snapshot volume and re-provision encrypted. |
| **IAM User without MFA** (`iam-user-mfa-enabled`) | **1.5**: Ensure MFA is enabled for all IAM users with console passwords | **A.5.17**: Authentication Information<br>**A.5.15**: Access Control | **A.9.2.3**: Privileged Access Management<br>**A.9.4.2**: Secure Log-on | **PR.AC-1**: Credentials Issued<br>**PR.AC-7**: Users Authenticated | Single credential compromise allows immediate lateral movement and total account takeover. | Require virtual/hardware MFA devices via IAM condition policy (`aws:MultiFactorAuthPresent: true`) or migrate to IAM Identity Center. |

---

## 2. Framework Overviews

### ISO/IEC 27001:2022 (Annex A)
- **A.5 (Organizational Controls):** Defines access rights (A.5.15), authentication information (A.5.17), and supplier relationships (A.5.19, A.5.20).
- **A.8 (Technological Controls):** Enforces network security (A.8.20), network services (A.8.21), cryptography (A.8.24), and technical vulnerability management (A.8.8).

### NIST Cybersecurity Framework (CSF v2.0)
- **Protect (PR.AC):** Identity management, authentication, and access control.
- **Protect (PR.DS):** Data security, ensuring data-at-rest and data-in-transit protections.
- **Protect (PR.PT):** Protective technology and network boundary defenses.
- **Detect (DE.CM):** Continuous security monitoring and configuration baseline verification.

### CIS AWS Foundations Benchmark v1.4.0
Prescriptive security configuration guidelines for Amazon Web Services spanning Identity and Access Management, Storage, Logging, and Networking.
