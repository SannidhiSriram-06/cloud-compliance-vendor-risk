#!/usr/bin/env python3
"""
Lightweight Self-Hosted GRC Risk Dashboard
==========================================
Displays automated cloud compliance findings, mapped ISO 27001 / NIST CSF controls,
SLA tracking, and Third-Party Vendor Risk Assessment scoring.
"""

import os
import json
from flask import Flask, render_template, jsonify

app = Flask(__name__)

RISK_REGISTER_FILE = os.environ.get(
    "RISK_REGISTER_FILE",
    os.path.join(os.path.dirname(__file__), "../../lambda/sample_risk_register.json")
)
VENDOR_ASSESSMENT_FILE = os.environ.get(
    "VENDOR_ASSESSMENT_FILE",
    os.path.join(os.path.dirname(__file__), "../../vendor-risk/sample_vendor_assessment.json")
)


def load_json(filepath):
    if os.path.exists(filepath):
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            print(f"Error loading {filepath}: {e}")
    return []


@app.route("/")
def dashboard():
    findings = load_json(RISK_REGISTER_FILE)
    if isinstance(findings, dict):
        findings = [findings]
    vendor_data = load_json(VENDOR_ASSESSMENT_FILE)
    if not isinstance(vendor_data, dict):
        vendor_data = {}

    # Calculate statistics
    total_findings = len(findings)
    high_count = sum(1 for f in findings if f.get("Severity") in ["CRITICAL", "HIGH"])
    medium_count = sum(1 for f in findings if f.get("Severity") == "MEDIUM")
    avg_score = round(sum(f.get("RiskScore", 0) for f in findings) / total_findings, 1) if total_findings > 0 else 0

    return render_template(
        "index.html",
        findings=findings,
        vendor=vendor_data,
        stats={
            "total": total_findings,
            "high": high_count,
            "medium": medium_count,
            "avg_score": avg_score
        }
    )


@app.route("/api/risk-register")
def api_register():
    return jsonify(load_json(RISK_REGISTER_FILE))


@app.route("/api/vendor-risk")
def api_vendor():
    return jsonify(load_json(VENDOR_ASSESSMENT_FILE))


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port, debug=False)
