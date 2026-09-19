#!/usr/bin/env python3
"""
Vendor Risk Assessment & Scoring Engine
========================================
Simulates a Third-Party Risk Management (TPRM) workflow. Evaluates vendor
responses against security controls (SOC 2, ISO 27001, NIST CSF, CIS Benchmarks),
calculates category-weighted risk ratings, flags critical compliance gaps, and
generates executive risk assessment reports.
"""

import sys
import os
import csv
import json
import argparse
from datetime import datetime, timezone

QUESTIONNAIRE_CSV = os.path.join(os.path.dirname(__file__), "vendor_intake_questionnaire.csv")

# Rating weight multipliers for vendor answers
RESPONSE_SCORES = {
    "YES": 1.0,          # Control fully implemented
    "PARTIAL": 0.5,      # Partially implemented / compensating control
    "NO": 0.0,           # Not implemented (deficiency)
    "NOT_APPLICABLE": 1.0 # Out of scope
}


def load_questionnaire(csv_path: str) -> list:
    """Loads standardized intake questions from CSV."""
    questions = []
    if not os.path.exists(csv_path):
        raise FileNotFoundError(f"Questionnaire template not found at: {csv_path}")

    with open(csv_path, mode="r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            row["Weight"] = int(row.get("Weight", 3))
            questions.append(row)
    return questions


def calculate_vendor_score(vendor_name: str, answers: dict, questions: list) -> dict:
    """
    Evaluates vendor answers, weights by criticality, and calculates category
    scores, overall risk rating, and control deficiencies.
    """
    category_data = {}
    critical_gaps = []
    total_weighted_points = 0.0
    total_possible_points = 0.0

    for q in questions:
        qid = q["Question_ID"]
        category = q["Category"]
        weight = q["Weight"]
        standard = q["Required_Standard"]
        question_text = q["Question"]

        ans = answers.get(qid, "NO").upper().strip()
        multiplier = RESPONSE_SCORES.get(ans, 0.0)

        points_earned = weight * multiplier
        max_points = weight * 1.0

        total_weighted_points += points_earned
        total_possible_points += max_points

        if category not in category_data:
            category_data[category] = {"earned": 0.0, "possible": 0.0, "gaps": 0}

        category_data[category]["earned"] += points_earned
        category_data[category]["possible"] += max_points

        if ans in ["NO", "PARTIAL"]:
            gap_info = {
                "question_id": qid,
                "category": category,
                "question": question_text,
                "response": ans,
                "weight": weight,
                "required_standard": standard,
                "severity": "CRITICAL" if weight >= 5 and ans == "NO" else ("HIGH" if weight >= 4 else "MEDIUM")
            }
            critical_gaps.append(gap_info)
            category_data[category]["gaps"] += 1

    overall_compliance_pct = round((total_weighted_points / total_possible_points) * 100, 2) if total_possible_points > 0 else 0.0

    # Risk Tiering logic
    # Inherent risk vs Residual risk
    if overall_compliance_pct >= 85 and not any(g["severity"] == "CRITICAL" for g in critical_gaps):
        residual_risk_level = "LOW"
        recommended_decision = "APPROVED - Annual Review Cycle"
    elif overall_compliance_pct >= 70:
        residual_risk_level = "MEDIUM"
        recommended_decision = "CONDITIONALLY APPROVED - Remediation Plan Required (90 Days)"
    else:
        residual_risk_level = "HIGH"
        recommended_decision = "REJECTED / HIGH RISK - Immediate Security Escalation"

    category_summary = {}
    for cat, stats in category_data.items():
        pct = round((stats["earned"] / stats["possible"]) * 100, 1) if stats["possible"] > 0 else 0.0
        category_summary[cat] = {
            "score_pct": pct,
            "earned": stats["earned"],
            "possible": stats["possible"],
            "deficiencies": stats["gaps"]
        }

    return {
        "vendor_name": vendor_name,
        "assessment_date": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        "compliance_score_pct": overall_compliance_pct,
        "residual_risk_level": residual_risk_level,
        "recommended_decision": recommended_decision,
        "category_breakdown": category_summary,
        "total_questions_evaluated": len(questions),
        "total_deficiencies_identified": len(critical_gaps),
        "critical_gaps": critical_gaps
    }


def generate_markdown_report(result: dict) -> str:
    """Generates an executive Third-Party Risk Assessment markdown report."""
    md = []
    md.append(f"# Third-Party Vendor Risk Assessment: {result['vendor_name']}\n")
    md.append("> **Notice:** This assessment evaluates a **FICTIONAL vendor** with **SIMULATED questionnaire responses** for TPRM demonstration purposes.\n")
    md.append(f"**Assessment Date:** {result['assessment_date']}  ")
    md.append(f"**Residual Risk Rating:** `{result['residual_risk_level']}`  ")
    md.append(f"**Overall Compliance Score:** `{result['compliance_score_pct']}%`  ")
    md.append(f"**Decision Recommendation:** **{result['recommended_decision']}**\n")
    md.append("---\n")

    md.append("## 1. Executive Summary\n")
    md.append(f"The vendor **{result['vendor_name']}** completed security intake evaluation covering ")
    md.append(f"{result['total_questions_evaluated']} controls across cloud governance, identity, encryption, and operational resilience. ")
    md.append(f"A total of **{result['total_deficiencies_identified']} security deficiencies** were identified.\n")

    md.append("## 2. Category Compliance Breakdown\n")
    md.append("| Category | Compliance Score | Status | Control Deficiencies |")
    md.append("| :--- | :---: | :---: | :---: |")
    for cat, data in result["category_breakdown"].items():
        status = "🟢 Satisfactory" if data["score_pct"] >= 80 else ("🟡 Needs Improvement" if data["score_pct"] >= 60 else "🔴 High Risk")
        md.append(f"| {cat} | {data['score_pct']}% | {status} | {data['deficiencies']} |")
    md.append("\n")

    md.append("## 3. Identified Deficiencies & Compliance Gaps\n")
    if not result["critical_gaps"]:
        md.append("✅ *No security deficiencies identified. Vendor satisfies all evaluated baseline controls.*\n")
    else:
        md.append("| ID | Severity | Control Question | Response | Required Standard |")
        md.append("| :--- | :---: | :--- | :---: | :--- |")
        for gap in result["critical_gaps"]:
            sev_badge = f"🔴 {gap['severity']}" if gap["severity"] in ["CRITICAL", "HIGH"] else f"🟡 {gap['severity']}"
            md.append(f"| `{gap['question_id']}` | {sev_badge} | {gap['question']} | `{gap['response']}` | {gap['required_standard']} |")
        md.append("\n")

    md.append("## 4. Remediation Action Plan & Contractual Requirements\n")
    md.append("To mitigate third-party exposure, the following contractual stipulations must be executed:")
    md.append("1. **Corrective Action Plan (CAP):** Vendor must submit a written remediation roadmap within 30 calendar days for all High/Critical gaps.")
    md.append("2. **Audit Rights & Attestation:** Annual re-certification and presentation of refreshed SOC 2 Type II or ISO 27001 certificates.")
    md.append("3. **Security Incident Notification:** Strict notification SLA of 72 hours in the event of confirmed or suspected compromise.")

    return "\n".join(md)


def main():
    parser = argparse.ArgumentParser(description="Vendor Risk Assessment & Scoring Engine")
    parser.add_argument("--vendor", default="Apex Cloud Analytics Inc.", help="Vendor name")
    parser.add_argument("--sample", action="store_true", default=True, help="Run sample evaluation")
    parser.add_argument("--output-json", default="sample_vendor_assessment.json", help="Output JSON path")
    parser.add_argument("--output-report", default="sample_vendor_report.md", help="Output Markdown report path")
    args = parser.parse_args()

    questions = load_questionnaire(QUESTIONNAIRE_CSV)

    # Simulated vendor answers reflecting typical third-party audit scenario
    sample_answers = {
        "VND-DP-01": "YES",     # AES-256 KMS encryption enabled
        "VND-DP-02": "YES",     # TLS 1.3 in transit
        "VND-DP-03": "PARTIAL", # Multi-tenant separation relies on software role-based filters rather than separate VPCs
        "VND-AC-01": "YES",     # MFA enforced on all admin accounts
        "VND-AC-02": "PARTIAL", # Credentials rotated semi-annually (180 days) instead of 90 days/JIT
        "VND-AC-03": "NO",      # Missing formal quarterly access review sign-offs
        "VND-IR-01": "YES",     # 72-hour breach notification SLA in contract
        "VND-IR-02": "YES",     # Tabletop exercise completed
        "VND-CO-01": "NO",      # Lacks automated continuous CIS benchmark scanning on AWS
        "VND-CO-02": "YES",     # IaC scanning in CI/CD pipeline
        "VND-GV-01": "YES",     # SOC 2 Type II clean report on file
        "VND-GV-02": "PARTIAL", # ISO 27001 audit in progress, not yet certified
        "VND-BC-01": "YES",     # RTO < 4h, RPO < 1h tested
        "VND-TP-01": "PARTIAL"  # 4th-party sub-processors audited ad-hoc
    }

    result = calculate_vendor_score(args.vendor, sample_answers, questions)
    report_md = generate_markdown_report(result)

    # Write files
    script_dir = os.path.dirname(__file__)
    json_path = os.path.join(script_dir, args.output_json)
    md_path = os.path.join(script_dir, args.output_report)

    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2)

    with open(md_path, "w", encoding="utf-8") as f:
        f.write(report_md)

    print(f"[+] Vendor Risk Assessment Complete for: {args.vendor}")
    print(f"[+] Compliance Score: {result['compliance_score_pct']}% | Risk: {result['residual_risk_level']}")
    print(f"[+] Decision: {result['recommended_decision']}")
    print(f"[+] Generated JSON: {json_path}")
    print(f"[+] Generated Report: {md_path}")


if __name__ == "__main__":
    main()
