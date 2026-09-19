#!/usr/bin/env python3
"""
Risk Register Processor Lambda Function
========================================
Processes AWS Security Hub (ASFF) findings and AWS Config compliance events
received via Amazon EventBridge, maps findings to ISO 27001:2022 / NIST CSF v2.0
frameworks, calculates risk scores and remediation SLAs, and persists the
findings into an automated GRC Risk Register (JSON & CSV) in Amazon S3.
"""

import os
import json
import csv
import io
import logging
from datetime import datetime, timezone

try:
    import boto3
    s3_client = boto3.client("s3")
except ImportError:
    s3_client = None

logger = logging.getLogger()
logger.setLevel(logging.INFO)

RISK_REGISTER_BUCKET = os.environ.get("RISK_REGISTER_BUCKET", "")
ENVIRONMENT = os.environ.get("ENVIRONMENT", "sandbox")

# Comprehensive Compliance Mapping Dictionary
# Maps rule patterns / keywords to ISO 27001, NIST CSF, and CIS AWS Foundations Benchmark
COMPLIANCE_MAPPINGS = {
    "s3-bucket-public-read-prohibited": {
        "rule_key": "S3_PUBLIC_READ",
        "iso_27001_2022": "A.5.15 (Access Control), A.8.24 (Use of Cryptography)",
        "iso_27001_2013": "A.9.4.2 (Secure Log-on), A.13.1.1 (Network Controls)",
        "nist_csf": "PR.AC-3 (Remote Access Management), PR.DS-1 (Data-at-Rest Protection)",
        "cis_aws_benchmark": "2.1.5 (Ensure S3 Bucket Access is Restricted)",
        "risk_category": "Data Exposure / Confidentiality",
        "default_severity": "HIGH",
        "remediation": "Apply S3 Public Access Block at account and bucket level. Remove open principal wildcard (*) from bucket policy."
    },
    "restricted-ssh": {
        "rule_key": "EC2_OPEN_SSH_0000_0",
        "iso_27001_2022": "A.8.20 (Network Security), A.8.21 (Security of Network Services)",
        "iso_27001_2013": "A.13.1.1 (Network Controls), A.13.1.2 (Security of Network Services)",
        "nist_csf": "PR.AC-5 (Network Integrity & Access Controls), PR.PT-4 (Network Protection)",
        "cis_aws_benchmark": "5.2 (Ensure no security groups allow ingress from 0.0.0.0/0 to port 22)",
        "risk_category": "Network Exposure / Unauthorized Access",
        "default_severity": "HIGH",
        "remediation": "Update security group rules to restrict port 22 to specific bastion or VPN CIDR ranges, or replace SSH with AWS Systems Manager Session Manager."
    },
    "encrypted-volumes": {
        "rule_key": "EBS_UNENCRYPTED",
        "iso_27001_2022": "A.8.24 (Use of Cryptography)",
        "iso_27001_2013": "A.10.1.1 (Policy on the Use of Cryptographic Controls)",
        "nist_csf": "PR.DS-1 (Data-at-Rest Protection)",
        "cis_aws_benchmark": "2.2.1 (Ensure EBS Volume Encryption is Enabled in All Regions)",
        "risk_category": "Data Confidentiality / Cryptographic Controls",
        "default_severity": "MEDIUM",
        "remediation": "Enable EBS default encryption using AWS KMS (aws/ebs or customer-managed CMK). Snapshot volume and re-create with encryption enabled."
    },
    "iam-user-mfa-enabled": {
        "rule_key": "IAM_NO_MFA",
        "iso_27001_2022": "A.5.17 (Authentication Information), A.5.15 (Access Control)",
        "iso_27001_2013": "A.9.2.3 (Management of Privileged Access Rights), A.9.4.2 (Secure Log-on)",
        "nist_csf": "PR.AC-1 (Identities and Credentials Issued), PR.AC-7 (Users Authenticated)",
        "cis_aws_benchmark": "1.5 (Ensure MFA is enabled for all IAM users with a console password)",
        "risk_category": "Identity Governance / Credential Compromise",
        "default_severity": "HIGH",
        "remediation": "Enforce virtual or hardware MFA via IAM policy (aws:MultiFactorAuthPresent) or migrate IAM users to AWS IAM Identity Center (SSO)."
    }
}

SLA_MATRIX = {
    "CRITICAL": {"days": 1, "score": 10},
    "HIGH": {"days": 7, "score": 8},
    "MEDIUM": {"days": 30, "score": 5},
    "LOW": {"days": 90, "score": 2},
    "INFORMATIONAL": {"days": 180, "score": 1}
}


def find_control_mapping(text_identifier: str) -> dict:
    """Matches finding identifiers/descriptions against our GRC compliance dictionary."""
    text_lower = text_identifier.lower()
    for rule_name, mapping in COMPLIANCE_MAPPINGS.items():
        if rule_name in text_lower:
            return mapping
        if mapping["rule_key"].lower() in text_lower:
            return mapping

    # Fallback keyword matching
    if "s3" in text_lower and ("public" in text_lower or "bucket" in text_lower):
        return COMPLIANCE_MAPPINGS["s3-bucket-public-read-prohibited"]
    if "ssh" in text_lower or "22" in text_lower or "security group" in text_lower:
        return COMPLIANCE_MAPPINGS["restricted-ssh"]
    if "ebs" in text_lower or "encrypt" in text_lower or "volume" in text_lower:
        return COMPLIANCE_MAPPINGS["encrypted-volumes"]
    if "mfa" in text_lower or "iam" in text_lower or "password" in text_lower:
        return COMPLIANCE_MAPPINGS["iam-user-mfa-enabled"]

    return {
        "rule_key": "GENERAL_CLOUD_MISCONFIGURATION",
        "iso_27001_2022": "A.5.15 (Access Control), A.8.8 (Management of Technical Vulnerabilities)",
        "iso_27001_2013": "A.12.6.1 (Management of Technical Vulnerabilities)",
        "nist_csf": "DE.CM-1 (Network and Asset Monitoring)",
        "cis_aws_benchmark": "General Foundations Benchmark",
        "risk_category": "Cloud Governance",
        "default_severity": "MEDIUM",
        "remediation": "Investigate resource configuration and apply least-privilege security controls."
    }


def parse_security_hub_finding(detail: dict) -> list:
    """Parses AWS Security Hub ASFF (AWS Security Finding Format) findings."""
    parsed_findings = []
    findings = detail.get("findings", [])
    if not findings and "Title" in detail:
        findings = [detail]

    for finding in findings:
        compliance = finding.get("Compliance", {})
        status = compliance.get("Status", "FAILED")

        # Process non-compliant findings
        if status in ["FAILED", "WARNING"]:
            finding_id = finding.get("Id", "unknown-id")
            title = finding.get("Title", "Untitled Security Hub Finding")
            desc = finding.get("Description", "")
            severity = finding.get("Severity", {}).get("Label", "MEDIUM").upper()
            created_at = finding.get("CreatedAt", datetime.now(timezone.utc).isoformat())

            resources = finding.get("Resources", [])
            resource_id = resources[0].get("Id", "Unknown-Resource") if resources else "Unknown-Resource"
            resource_type = resources[0].get("Type", "Unknown-Type") if resources else "Unknown-Type"

            mapping = find_control_mapping(f"{title} {desc} {finding_id}")
            effective_severity = severity if severity in SLA_MATRIX else mapping["default_severity"]
            sla_info = SLA_MATRIX.get(effective_severity, SLA_MATRIX["MEDIUM"])

            parsed_findings.append({
                "FindingID": finding_id,
                "Source": "AWS Security Hub",
                "Title": title,
                "Description": desc[:250],
                "ResourceType": resource_type,
                "ResourceID": resource_id,
                "Severity": effective_severity,
                "RiskScore": sla_info["score"],
                "RemediationSLA_Days": sla_info["days"],
                "ISO_27001_2022": mapping["iso_27001_2022"],
                "NIST_CSF": mapping["nist_csf"],
                "CIS_AWS_Benchmark": mapping["cis_aws_benchmark"],
                "RiskCategory": mapping["risk_category"],
                "RemediationAction": mapping["remediation"],
                "Status": "OPEN",
                "LoggedTimestamp": created_at,
                "Environment": ENVIRONMENT
            })

    return parsed_findings


def parse_config_event(detail: dict) -> list:
    """Parses AWS Config Rule Compliance Change events."""
    parsed_findings = []
    compliance_type = detail.get("newEvaluationResult", {}).get("complianceType", "")

    if compliance_type == "NON_COMPLIANT":
        rule_name = detail.get("configRuleName", "unknown-config-rule")
        eval_result = detail.get("newEvaluationResult", {})
        eval_qualifier = eval_result.get("evaluationResultIdentifier", {}).get("evaluationResultQualifier", {})
        resource_id = eval_qualifier.get("resourceId", "Unknown-Resource")
        resource_type = eval_qualifier.get("resourceType", "AWS::Resource")
        timestamp = eval_result.get("resultRecordedTime", datetime.now(timezone.utc).isoformat())

        mapping = find_control_mapping(rule_name)
        severity = mapping["default_severity"]
        sla_info = SLA_MATRIX.get(severity, SLA_MATRIX["MEDIUM"])

        finding_id = f"config-{rule_name}-{resource_id}"
        parsed_findings.append({
            "FindingID": finding_id,
            "Source": "AWS Config",
            "Title": f"AWS Config Rule Failed: {rule_name}",
            "Description": f"Resource {resource_id} violated compliance rule {rule_name}",
            "ResourceType": resource_type,
            "ResourceID": resource_id,
            "Severity": severity,
            "RiskScore": sla_info["score"],
            "RemediationSLA_Days": sla_info["days"],
            "ISO_27001_2022": mapping["iso_27001_2022"],
            "NIST_CSF": mapping["nist_csf"],
            "CIS_AWS_Benchmark": mapping["cis_aws_benchmark"],
            "RiskCategory": mapping["risk_category"],
            "RemediationAction": mapping["remediation"],
            "Status": "OPEN",
            "LoggedTimestamp": str(timestamp),
            "Environment": ENVIRONMENT
        })

    return parsed_findings


def load_existing_register_from_s3(bucket: str, key: str) -> list:
    """Loads existing risk register JSON from S3 if available."""
    if not s3_client or not bucket:
        return []
    try:
        resp = s3_client.get_object(Bucket=bucket, Key=key)
        content = resp["Body"].read().decode("utf-8")
        return json.loads(content)
    except Exception as e:
        logger.warning(f"Could not load existing register from S3 ({key}): {e}")
        return []


def write_risk_register_to_s3(bucket: str, register_data: list):
    """Writes updated risk register data to S3 in both JSON and CSV format."""
    if not s3_client or not bucket:
        logger.warning("S3 client or RISK_REGISTER_BUCKET not configured. Skipping S3 upload.")
        return

    # Write JSON
    json_body = json.dumps(register_data, indent=2)
    s3_client.put_object(
        Bucket=bucket,
        Key="risk_register.json",
        Body=json_body.encode("utf-8"),
        ContentType="application/json"
    )
    logger.info(f"Successfully updated s3://{bucket}/risk_register.json ({len(register_data)} entries)")

    # Write CSV
    if register_data:
        output = io.StringIO()
        fieldnames = list(register_data[0].keys())
        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(register_data)

        s3_client.put_object(
            Bucket=bucket,
            Key="risk_register.csv",
            Body=output.getvalue().encode("utf-8"),
            ContentType="text/csv"
        )
        logger.info(f"Successfully updated s3://{bucket}/risk_register.csv")


def lambda_handler(event, context):
    """Main Lambda entrypoint triggered by EventBridge."""
    logger.info("Received EventBridge event: %s", json.dumps(event))

    source = event.get("source", "")
    detail = event.get("detail", {})
    new_findings = []

    if source == "aws.securityhub":
        new_findings = parse_security_hub_finding(detail)
    elif source == "aws.config":
        new_findings = parse_config_event(detail)
    else:
        # Fallback inspection for manual test payloads
        if "findings" in detail or "Findings" in detail:
            new_findings = parse_security_hub_finding(detail)
        elif "newEvaluationResult" in detail:
            new_findings = parse_config_event(detail)
        else:
            logger.warning("Unrecognized event source: %s", source)

    if not new_findings:
        logger.info("No compliance failure findings to record.")
        return {"statusCode": 200, "message": "No non-compliant findings detected"}

    # Merge with existing register
    existing_register = load_existing_register_from_s3(RISK_REGISTER_BUCKET, "risk_register.json")
    existing_map = {item["FindingID"]: item for item in existing_register}

    for finding in new_findings:
        existing_map[finding["FindingID"]] = finding

    updated_register = list(existing_map.values())

    # Sort by RiskScore descending
    updated_register.sort(key=lambda x: x.get("RiskScore", 0), reverse=True)

    # Persist to S3
    write_risk_register_to_s3(RISK_REGISTER_BUCKET, updated_register)

    return {
        "statusCode": 200,
        "processed_findings_count": len(new_findings),
        "total_register_entries": len(updated_register),
        "sample_finding": new_findings[0] if new_findings else None
    }


if __name__ == "__main__":
    # Local CLI test execution
    print("[*] Running local test evaluation of Risk Register Processor...")
    sample_event = {
        "source": "aws.securityhub",
        "detail-type": "Security Hub Findings - Imported",
        "detail": {
            "findings": [
                {
                    "Id": "arn:aws:securityhub:us-east-1:123456789012:finding/s3-public-read-demo",
                    "Title": "S3 Buckets should prohibit public read access",
                    "Description": "Bucket cloud-compliance-demo-public-demo has unrestricted public read access enabled via bucket policy.",
                    "Severity": {"Label": "HIGH"},
                    "Resources": [{"Id": "arn:aws:s3:::cloud-compliance-demo-public-demo", "Type": "AwsS3Bucket"}],
                    "Compliance": {"Status": "FAILED"},
                    "CreatedAt": datetime.now(timezone.utc).isoformat()
                },
                {
                    "Id": "arn:aws:securityhub:us-east-1:123456789012:finding/open-ssh-demo",
                    "Title": "Security Groups should not allow ingress from 0.0.0.0/0 to port 22",
                    "Description": "Security group sg-0123456789abcdef0 allows inbound traffic on SSH port 22 from any IP.",
                    "Severity": {"Label": "HIGH"},
                    "Resources": [{"Id": "sg-0123456789abcdef0", "Type": "AwsEc2SecurityGroup"}],
                    "Compliance": {"Status": "FAILED"},
                    "CreatedAt": datetime.now(timezone.utc).isoformat()
                }
            ]
        }
    }

    result = lambda_handler(sample_event, None)
    print(json.dumps(result, indent=2))
