# Third-Party Vendor Risk Assessment: Apex Cloud Analytics Inc.

**Assessment Date:** 2026-09-19  
**Residual Risk Rating:** `MEDIUM`  
**Overall Compliance Score:** `74.56%`  
**Decision Recommendation:** **CONDITIONALLY APPROVED - Remediation Plan Required (90 Days)**

---

## 1. Executive Summary

The vendor **Apex Cloud Analytics Inc.** completed security intake evaluation covering 
14 controls across cloud governance, identity, encryption, and operational resilience. 
A total of **6 security deficiencies** were identified.

## 2. Category Compliance Breakdown

| Category | Compliance Score | Status | Control Deficiencies |
| :--- | :---: | :---: | :---: |
| Data Protection | 85.7% | 🟢 Satisfactory | 1 |
| Access & Identity | 58.3% | 🔴 High Risk | 2 |
| Incident Response | 100.0% | 🟢 Satisfactory | 0 |
| Cloud Operations | 42.9% | 🔴 High Risk | 1 |
| Compliance & Governance | 77.8% | 🟡 Needs Improvement | 1 |
| Resilience & DR | 100.0% | 🟢 Satisfactory | 0 |
| Subcontractor Risk | 50.0% | 🔴 High Risk | 1 |


## 3. Identified Deficiencies & Compliance Gaps

| ID | Severity | Control Question | Response | Required Standard |
| :--- | :---: | :--- | :---: | :--- |
| `VND-DP-03` | 🔴 HIGH | Does the vendor maintain logical data segregation between multi-tenant customer environments? | `PARTIAL` | SOC 2 CC6.1 / ISO 27001 A.8.20 |
| `VND-AC-02` | 🔴 HIGH | Are privileged access credentials rotated at least every 90 days or generated just-in-time (JIT)? | `PARTIAL` | ISO 27001 A.5.17 / NIST PR.AC-1 |
| `VND-AC-03` | 🟡 MEDIUM | Does the vendor perform quarterly user access reviews (UAR) for personnel with infrastructure access? | `NO` | SOC 2 CC6.3 / ISO 27001 A.5.18 |
| `VND-CO-01` | 🔴 HIGH | Are cloud environments continuously monitored with automated CIS Benchmark compliance scanning (e.g. AWS Config / Security Hub)? | `NO` | CIS Benchmark 2.1 / NIST DE.CM-1 |
| `VND-GV-02` | 🔴 HIGH | Is the organization certified against ISO/IEC 27001:2022 by an accredited certification body? | `PARTIAL` | ISO 27001 / NIST CSF |
| `VND-TP-01` | 🟡 MEDIUM | Does the vendor evaluate and continuously monitor 4th-party sub-processors handling customer data? | `PARTIAL` | ISO 27001 A.5.19 / NIST ID.SC-1 |


## 4. Remediation Action Plan & Contractual Requirements

To mitigate third-party exposure, the following contractual stipulations must be executed:
1. **Corrective Action Plan (CAP):** Vendor must submit a written remediation roadmap within 30 calendar days for all High/Critical gaps.
2. **Audit Rights & Attestation:** Annual re-certification and presentation of refreshed SOC 2 Type II or ISO 27001 certificates.
3. **Security Incident Notification:** Strict notification SLA of 72 hours in the event of confirmed or suspected compromise.