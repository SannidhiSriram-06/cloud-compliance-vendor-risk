#!/usr/bin/env python3
"""
Risk Register Processor Lambda Function
========================================
Processes AWS Security Hub (ASFF) findings and AWS Config compliance events
received via Amazon EventBridge, maps findings to ISO 27001:2022 / NIST CSF v1.1
frameworks, calculates risk scores and remediation SLAs, and persists the
findings into an automated GRC Risk Register (JSON & CSV) in Amazon S3.

Idempotent & Concurrency-Safe:
Writes individual finding objects under `findings/<sha256-of-canonical-key>.json`,
then rebuilds `risk_register.json` and `risk_register.csv` from the full listing
of `findings/`. Cross-source findings (AWS Config + Security Hub) for the same
underlying resource and control deduplicate into a single row with multiple Sources.

Mapping Semantics:
- `CIS_Match`: "exact" only where CIS control number was taken directly from
  Security Hub's Compliance.RelatedRequirements or matches the Config rule's documented
  CIS control; otherwise "closest".
- `ISO_NIST_Basis`: "analyst-assigned (indicative)" across all rows, as ISO 27001:2022
  Annex A and NIST CSF v1.1 alignments represent an expert-curated crosswalk rather than
  an official AWS/ISO joint specification.
"""

import os
import re
import json
import csv
import io
import hashlib
import logging
from datetime import datetime, timezone

try:
    import boto3
    s3_client = boto3.client("s3")
    config_client = boto3.client("config")
except ImportError:
    s3_client = None
    config_client = None

logger = logging.getLogger()
logger.setLevel(logging.INFO)

RISK_REGISTER_BUCKET = os.environ.get("RISK_REGISTER_BUCKET", "")
ENVIRONMENT = os.environ.get("ENVIRONMENT", "sandbox")

# COMPLIANCE_MAPPINGS re-keyed by CIS AWS Foundations Benchmark v1.4.0 control numbers,
# plus Config managed rule aliases.
# Mapping Rationale & Audit Decisions:
# 1. CIS 1.10 (IAM console user MFA): Direct match from live finding RelatedRequirements.
# 2. CIS 2.1.3 (S3 MFA Delete): Dropped PR.IP-4 (stretch; backups) in favor of PR.DS-1
#    (Data-at-rest protection against unauthorized permanent object tampering) and A.8.10.
# 3. CIS 3.1 (CloudTrail multi-region): Mapped to DE.CM-1 (monitoring coverage of network
#    and assets) and PR.PT-1 (audit log generation and integrity), replacing DE.AE-1.
# 4. CIS 3.9 (VPC flow logs): Mapped to DE.CM-1 (network traffic and communication monitoring)
#    and A.8.20 (network controls).
# 5. CIS 1.17 (AWS Support role): Marked CIS_Match = "closest" (operational readiness).
COMPLIANCE_MAPPINGS = {
    # 1.10 - IAM MFA for console users
    "1.10": {
        "rule_key": "CIS_1.10_IAM_USER_MFA",
        "cis_number": "1.10",
        "title": "Ensure MFA is enabled for all IAM users that have a console password",
        "iso_27001_2022": "A.5.17 (Authentication Information), A.5.15 (Access Control)",
        "nist_csf": "PR.AC-1 (Identities and Credentials Issued), PR.AC-7 (Users Authenticated)",
        "cis_aws_benchmark": "1.10 (Ensure MFA is enabled for all IAM users that have a console password)",
        "risk_category": "Identity Governance / Credential Compromise",
        "default_severity": "HIGH",
        "remediation": "Enforce virtual or hardware MFA via IAM policy (aws:MultiFactorAuthPresent) or migrate IAM users to AWS IAM Identity Center (SSO).",
        "cis_match": "exact"
    },
    # 2.1.5 - S3 Block Public Access / public read prohibited
    "2.1.5": {
        "rule_key": "CIS_2.1.5_S3_PUBLIC_READ",
        "cis_number": "2.1.5",
        "title": "Ensure that S3 Buckets are configured with 'Block Public Access' / prohibit public read",
        "iso_27001_2022": "A.5.15 (Access Control), A.8.24 (Use of Cryptography)",
        "nist_csf": "PR.AC-3 (Remote Access Management), PR.DS-1 (Data-at-Rest Protection)",
        "cis_aws_benchmark": "2.1.5 (Ensure S3 Bucket Access is Restricted)",
        "risk_category": "Data Exposure / Confidentiality",
        "default_severity": "HIGH",
        "remediation": "Apply S3 Public Access Block at account and bucket level. Remove open principal wildcard (*) from bucket policy.",
        "cis_match": "exact"
    },
    # 5.2 - Security groups unrestricted incoming SSH (port 22)
    "5.2": {
        "rule_key": "CIS_5.2_EC2_RESTRICTED_SSH",
        "cis_number": "5.2",
        "title": "Ensure no security groups allow ingress from 0.0.0.0/0 to port 22",
        "iso_27001_2022": "A.8.20 (Network Security), A.8.21 (Security of Network Services)",
        "nist_csf": "PR.AC-5 (Network Integrity & Access Controls), PR.PT-4 (Network Protection)",
        "cis_aws_benchmark": "5.2 (Ensure no security groups allow ingress from 0.0.0.0/0 to port 22)",
        "risk_category": "Network Exposure / Unauthorized Access",
        "default_severity": "HIGH",
        "remediation": "Update security group rules to restrict port 22 to specific bastion or VPN CIDR ranges, or replace SSH with AWS Systems Manager Session Manager.",
        "cis_match": "exact"
    },
    # 2.2.1 - EBS encryption (Note: Config rule evaluates attached volumes; CIS 2.2.1 evaluates default encryption)
    "2.2.1": {
        "rule_key": "CIS_2.2.1_EBS_ENCRYPTED",
        "cis_number": "2.2.1",
        "title": "Ensure EBS volume encryption is enabled",
        "iso_27001_2022": "A.8.24 (Use of Cryptography)",
        "nist_csf": "PR.DS-1 (Data-at-Rest Protection)",
        "cis_aws_benchmark": "2.2.1 (Ensure EBS Volume Encryption is Enabled)",
        "risk_category": "Data Confidentiality / Cryptographic Controls",
        "default_severity": "MEDIUM",
        "remediation": "Enable EBS default encryption using AWS KMS (aws/ebs or customer-managed CMK). Snapshot volume and re-create with encryption enabled.",
        "cis_match": "closest"  # Closest: Config checks attached volume state while CIS checks account-level default KMS
    },
    # 2.1.2 - S3 TLS enforcement
    "2.1.2": {
        "rule_key": "CIS_2.1.2_S3_REQUIRE_TLS",
        "cis_number": "2.1.2",
        "title": "Ensure S3 bucket policy requires requests to use TLS",
        "iso_27001_2022": "A.8.20 (Network Security), A.8.24 (Use of Cryptography)",
        "nist_csf": "PR.DS-2 (Data-in-Transit Protection), PR.PT-4 (Network Protection)",
        "cis_aws_benchmark": "2.1.2 (Ensure S3 Bucket Policy Requires Requests to Use TLS)",
        "risk_category": "Data Confidentiality / Cryptographic Controls",
        "default_severity": "MEDIUM",
        "remediation": "Attach bucket policy with Deny statement for Condition aws:SecureTransport = false.",
        "cis_match": "exact"
    },
    # 2.1.3 - S3 MFA Delete (Replaced PR.IP-4 stretch with PR.DS-1 data protection & deletion prevention)
    "2.1.3": {
        "rule_key": "CIS_2.1.3_S3_MFA_DELETE",
        "cis_number": "2.1.3",
        "title": "Ensure MFA Delete is enabled on S3 buckets",
        "iso_27001_2022": "A.8.10 (Information Deletion), A.5.15 (Access Control)",
        "nist_csf": "PR.DS-1 (Data-at-Rest Protection), PR.AC-4 (Access Permissions Enforced)",
        "cis_aws_benchmark": "2.1.3 (Ensure MFA Delete is Enabled on S3 Buckets)",
        "risk_category": "Data Exposure / Confidentiality",
        "default_severity": "LOW",
        "remediation": "Enable versioning and configure MFA Delete on the S3 bucket via the AWS CLI using root credentials.",
        "cis_match": "exact"
    },
    # 1.8 - Password policy minimum length 14
    "1.8": {
        "rule_key": "CIS_1.8_IAM_PASSWORD_LENGTH",
        "cis_number": "1.8",
        "title": "Ensure IAM password policy requires minimum password length of 14 or greater",
        "iso_27001_2022": "A.5.17 (Authentication Information)",
        "nist_csf": "PR.AC-1 (Identities and Credentials Issued)",
        "cis_aws_benchmark": "1.8 (Ensure IAM password policy requires minimum length of 14 or greater)",
        "risk_category": "Identity Governance / Credential Compromise",
        "default_severity": "MEDIUM",
        "remediation": "Update IAM account password policy to require MinimumPasswordLength >= 14.",
        "cis_match": "exact"
    },
    # 1.9 - Password policy prevent reuse
    "1.9": {
        "rule_key": "CIS_1.9_IAM_PASSWORD_REUSE",
        "cis_number": "1.9",
        "title": "Ensure IAM password policy prevents password reuse",
        "iso_27001_2022": "A.5.17 (Authentication Information)",
        "nist_csf": "PR.AC-1 (Identities and Credentials Issued)",
        "cis_aws_benchmark": "1.9 (Ensure IAM password policy prevents password reuse)",
        "risk_category": "Identity Governance / Credential Compromise",
        "default_severity": "LOW",
        "remediation": "Set password reuse prevention to 24 in IAM password policy.",
        "cis_match": "exact"
    },
    # 1.17 - AWS Support incident management role
    "1.17": {
        "rule_key": "CIS_1.17_SUPPORT_ROLE",
        "cis_number": "1.17",
        "title": "Ensure a support role has been created to manage incidents with AWS Support",
        "iso_27001_2022": "A.5.24 (Incident Management Planning)",
        "nist_csf": "RS.CO-1 (Personnel Know Roles in Response)",
        "cis_aws_benchmark": "1.17 (Ensure a support role has been created for AWS Support)",
        "risk_category": "Security Governance & Operations",
        "default_severity": "LOW",
        "remediation": "Create an IAM role with AWSSupportAccess managed policy attached.",
        "cis_match": "closest"  # Closest: Support role facilitates response coordination but does not establish full IR capabilities
    },
    # 3.1 - CloudTrail multi-region enabled (Using DE.CM-1 asset monitoring and PR.PT-1 audit logging)
    "3.1": {
        "rule_key": "CIS_3.1_CLOUDTRAIL_MULTIREGION",
        "cis_number": "3.1",
        "title": "Ensure CloudTrail is enabled and configured with at least one multi-Region trail",
        "iso_27001_2022": "A.8.15 (Logging), A.8.16 (Monitoring Activities)",
        "nist_csf": "DE.CM-1 (Network and Asset Monitoring), PR.PT-1 (Audit Log Generation & Integrity)",
        "cis_aws_benchmark": "3.1 (Ensure CloudTrail is enabled across all regions)",
        "risk_category": "Logging & Monitoring / Audit Trail",
        "default_severity": "HIGH",
        "remediation": "Enable multi-Region CloudTrail with management event logging and log file validation.",
        "cis_match": "exact"
    },
    # 3.9 - VPC Flow Logging (Using DE.CM-1 network monitoring and A.8.20 network security)
    "3.9": {
        "rule_key": "CIS_3.9_VPC_FLOW_LOGS",
        "cis_number": "3.9",
        "title": "Ensure VPC flow logging is enabled in all VPCs",
        "iso_27001_2022": "A.8.15 (Logging), A.8.20 (Network Security)",
        "nist_csf": "DE.CM-1 (Network and Asset Monitoring), PR.PT-4 (Network Protection)",
        "cis_aws_benchmark": "3.9 (Ensure VPC flow logging is enabled in all VPCs)",
        "risk_category": "Logging & Monitoring / Audit Trail",
        "default_severity": "MEDIUM",
        "remediation": "Create VPC flow logs for all active and default VPCs to CloudWatch Logs or S3.",
        "cis_match": "exact"
    }
}

# Config rule name aliases pointing to CIS control keys
CONFIG_RULE_TO_CIS = {
    "s3-bucket-public-read-prohibited": "2.1.5",
    "restricted-ssh": "5.2",
    "encrypted-volumes": "2.2.1",
    "iam-user-mfa-enabled": "1.10"
}

# SecurityControlId to CIS control keys
SECURITY_CONTROL_TO_CIS = {
    "S3.8": "2.1.5",
    "S3.1": "2.1.5",
    "S3.5": "2.1.2",
    "S3.20": "2.1.3",
    "IAM.5": "1.10",
    "IAM.15": "1.8",
    "IAM.16": "1.9",
    "IAM.18": "1.17",
    "EC2.7": "2.2.1",
    "EC2.6": "3.9",
    "CloudTrail.1": "3.1"
}

# Rule-based simulated Owner assignment for portfolio demonstration
OWNER_ASSIGNMENT = {
    "identity": "Identity & Access Team",
    "data": "Data Protection Team",
    "network": "Network Security Team",
    "logging": "Security Operations",
    "monitoring": "Security Operations",
    "governance": "Cloud Platform Team"
}

SLA_MATRIX = {
    "CRITICAL": {"days": 1, "score": 10},
    "HIGH": {"days": 7, "score": 8},
    "MEDIUM": {"days": 30, "score": 5},
    "LOW": {"days": 90, "score": 2},
    "INFORMATIONAL": {"days": 180, "score": 1}
}


def assign_owner(risk_category: str) -> str:
    """Assigns an ownership team based on the finding's RiskCategory."""
    cat_lower = (risk_category or "").lower()
    if "network" in cat_lower or "ssh" in cat_lower:
        return OWNER_ASSIGNMENT["network"]
    if "identity" in cat_lower or "access" in cat_lower or "credential" in cat_lower:
        return OWNER_ASSIGNMENT["identity"]
    if "data" in cat_lower or "confidentiality" in cat_lower or "cryptograph" in cat_lower:
        return OWNER_ASSIGNMENT["data"]
    if "logging" in cat_lower or "monitoring" in cat_lower or "audit" in cat_lower or "trail" in cat_lower:
        return OWNER_ASSIGNMENT["logging"]
    return "Cloud Platform Team"


def normalize_resource_id(raw_id: str) -> str:
    """
    Normalizes an ARN or raw resource identifier to its bare ID.
    Special normalization: 'AWS::::Account:<id>' -> 'account'.
    """
    if not raw_id:
        return "Unknown-Resource"
    clean_id = raw_id.strip()

    # Normalize account-level findings
    if clean_id.startswith("AWS::::Account:"):
        return "account"

    if clean_id.startswith("arn:aws:"):
        parts = clean_id.split(":")
        leaf = parts[-1]
        if "/" in leaf:
            return leaf.split("/")[-1]
        return leaf
    return clean_id


def resolve_iam_username_from_config(resource_id: str, client=None) -> str:
    """
    Resolves an IAM User unique identifier (e.g. AIDAXWYOPVPW...) to the human-readable
    IAM user name using AWS Config BatchGetResourceConfig.
    Falls back to the raw resource_id on failure.
    """
    if not resource_id or not resource_id.startswith("AIDA"):
        return resource_id

    cfg = client or config_client
    if not cfg:
        logger.warning("Config client unavailable; skipping IAM username lookup for %s", resource_id)
        return resource_id

    try:
        resp = cfg.batch_get_resource_config(
            resourceKeys=[{"resourceType": "AWS::IAM::User", "resourceId": resource_id}]
        )
        items = resp.get("baseConfigurationItems", [])
        if items and items[0].get("resourceName"):
            user_name = items[0]["resourceName"]
            logger.info("Resolved IAM user ID %s -> %s via AWS Config", resource_id, user_name)
            return user_name
        logger.warning("No configuration item found for IAM user ID %s", resource_id)
    except Exception as e:
        logger.warning("Failed to lookup IAM user name for ID %s via Config: %s", resource_id, e)

    return resource_id


def extract_cis_number_from_finding(finding: dict) -> str:
    """Extracts CIS v1.4.0 control number from Compliance.RelatedRequirements or Title."""
    compliance = finding.get("Compliance", {})
    reqs = compliance.get("RelatedRequirements", [])
    for req in reqs:
        match = re.search(r"CIS AWS Foundations Benchmark v1\.4\.0/([\d.]+)", req)
        if match:
            return match.group(1)

    title = finding.get("Title", "")
    match = re.match(r"^(\d+(\.\d+)+)", title.strip())
    if match:
        return match.group(1)

    return ""


def find_control_mapping(
    rule_name: str = "",
    title: str = "",
    related_requirements: list = None,
    security_control_id: str = "",
    generator_id: str = ""
) -> tuple[dict, str]:
    """
    Matches finding identifiers against our GRC compliance dictionary.
    Priority order:
      1. CIS number from Compliance.RelatedRequirements (regex CIS AWS Foundations Benchmark v1.4.0/([\\d.]+))
      2. Known Config rule name (exact match from Config event OR Security Hub Title/GeneratorId)
      3. Compliance.SecurityControlId (e.g. S3.8, IAM.5)
      4. Normalized Title
    Returns (mapping_dict, canonical_control_key).
    """
    # 1. CIS number from RelatedRequirements
    if related_requirements:
        for req in related_requirements:
            match = re.search(r"CIS AWS Foundations Benchmark v1\.4\.0/([\d.]+)", req)
            if match:
                cis_num = match.group(1)
                if cis_num in COMPLIANCE_MAPPINGS:
                    res = dict(COMPLIANCE_MAPPINGS[cis_num])
                    res["ControlMapping"] = "MAPPED"
                    res["CIS_Match"] = res.get("cis_match", "exact")
                    res["ISO_NIST_Basis"] = "analyst-assigned (indicative)"
                    return res, f"CIS_{cis_num}"

    # 2. Known Config rule name (or title/generator equal to it)
    candidate_rules = [rule_name, title.strip(), generator_id.strip()]
    for cr in candidate_rules:
        if cr in CONFIG_RULE_TO_CIS:
            cis_num = CONFIG_RULE_TO_CIS[cr]
            res = dict(COMPLIANCE_MAPPINGS[cis_num])
            res["ControlMapping"] = "MAPPED"
            res["CIS_Match"] = res.get("cis_match", "exact")
            res["ISO_NIST_Basis"] = "analyst-assigned (indicative)"
            return res, f"CIS_{cis_num}"

    # 3. Compliance.SecurityControlId
    if security_control_id and security_control_id in SECURITY_CONTROL_TO_CIS:
        cis_num = SECURITY_CONTROL_TO_CIS[security_control_id]
        res = dict(COMPLIANCE_MAPPINGS[cis_num])
        res["ControlMapping"] = "MAPPED"
        res["CIS_Match"] = res.get("cis_match", "exact")
        res["ISO_NIST_Basis"] = "analyst-assigned (indicative)"
        return res, f"CIS_{cis_num}"

    # 4. Title regex check for CIS number
    if title:
        match = re.match(r"^(\d+(\.\d+)+)", title.strip())
        if match:
            cis_num = match.group(1)
            if cis_num in COMPLIANCE_MAPPINGS:
                res = dict(COMPLIANCE_MAPPINGS[cis_num])
                res["ControlMapping"] = "MAPPED"
                res["CIS_Match"] = res.get("cis_match", "exact")
                res["ISO_NIST_Basis"] = "analyst-assigned (indicative)"
                return res, f"CIS_{cis_num}"

    # Distinct unmapped fallback: control_key becomes SecurityControlId or normalized title
    control_key = security_control_id or re.sub(r"[^a-zA-Z0-9_-]", "_", title.strip())[:40] or "UNMAPPED_CONTROL"
    return {
        "rule_key": control_key,
        "ControlMapping": "UNMAPPED",
        "iso_27001_2022": "Not mapped",
        "nist_csf": "Not mapped",
        "cis_aws_benchmark": "Not mapped",
        "risk_category": "Cloud Governance / Unmapped Finding",
        "default_severity": "MEDIUM",
        "remediation": "Review finding in AWS Console and assess control remediation.",
        "CIS_Match": "none",
        "ISO_NIST_Basis": "analyst-assigned (indicative)"
    }, control_key


def parse_security_hub_finding(detail: dict) -> list:
    """Defensively parses AWS Security Hub ASFF findings."""
    parsed_findings = []
    if not isinstance(detail, dict):
        return []

    findings = detail.get("findings", [])
    if not isinstance(findings, list) and isinstance(findings, dict):
        findings = [findings]
    elif not findings and "Title" in detail:
        findings = [detail]

    for finding in findings:
        try:
            if not isinstance(finding, dict):
                continue

            compliance = finding.get("Compliance") or {}
            status = compliance.get("Status", "FAILED")
            if status != "FAILED":
                continue

            finding_id = finding.get("Id", "unknown-id")
            title = finding.get("Title", "Untitled Security Hub Finding")
            desc = finding.get("Description", "")
            raw_severity = finding.get("Severity", {})
            severity = "MEDIUM"
            if isinstance(raw_severity, dict):
                severity = raw_severity.get("Label", "MEDIUM").upper()
            elif isinstance(raw_severity, str):
                severity = raw_severity.upper()

            created_at = finding.get("CreatedAt", datetime.now(timezone.utc).isoformat())

            resources = finding.get("Resources", [])
            raw_resource_id = "Unknown-Resource"
            resource_type = "Unknown-Type"
            if isinstance(resources, list) and len(resources) > 0 and isinstance(resources[0], dict):
                raw_resource_id = resources[0].get("Id", "Unknown-Resource")
                resource_type = resources[0].get("Type", "Unknown-Type")

            normalized_id = normalize_resource_id(raw_resource_id)

            reqs = compliance.get("RelatedRequirements", [])
            sec_ctrl_id = compliance.get("SecurityControlId", "")
            gen_id = finding.get("GeneratorId", "")

            mapping, control_key = find_control_mapping(
                title=title,
                related_requirements=reqs,
                security_control_id=sec_ctrl_id,
                generator_id=gen_id
            )

            effective_severity = severity if severity in SLA_MATRIX else mapping["default_severity"]
            sla_info = SLA_MATRIX.get(effective_severity, SLA_MATRIX["MEDIUM"])
            owner = assign_owner(mapping.get("risk_category", ""))

            parsed_findings.append({
                "CanonicalKey": f"{control_key}:{normalized_id}",
                "ControlKey": control_key,
                "Source": "AWS Security Hub",
                "Sources": ["AWS Security Hub"],
                "FindingID": finding_id,
                "Title": title,
                "Description": desc[:250] if desc else "",
                "ResourceType": resource_type,
                "ResourceID": normalized_id,
                "RawResourceID": raw_resource_id,
                "Severity": effective_severity,
                "RiskScore": sla_info["score"],
                "RemediationSLA_Days": sla_info["days"],
                "Owner": owner,
                "ControlMapping": mapping["ControlMapping"],
                "CIS_Match": mapping.get("CIS_Match", "closest"),
                "ISO_NIST_Basis": mapping.get("ISO_NIST_Basis", "analyst-assigned (indicative)"),
                "ISO_27001_2022": mapping["iso_27001_2022"],
                "NIST_CSF": mapping["nist_csf"],
                "CIS_AWS_Benchmark": mapping["cis_aws_benchmark"],
                "RiskCategory": mapping["risk_category"],
                "RemediationAction": mapping["remediation"],
                "Status": "OPEN",
                "LoggedTimestamp": created_at,
                "Environment": ENVIRONMENT
            })
        except Exception as e:
            logger.error("Error parsing Security Hub finding: %s (finding: %s)", e, finding)
            continue

    return parsed_findings


def parse_config_event(detail: dict, cfg_client=None) -> list:
    """Defensively parses AWS Config Rule Compliance Change events."""
    parsed_findings = []
    if not isinstance(detail, dict):
        return []

    try:
        rule_name = detail.get("configRuleName", "unknown-config-rule")
        # Ignore Security Hub-managed Config rules to eliminate duplicate noise
        if rule_name.startswith("securityhub-"):
            logger.info("Ignoring Security Hub-managed Config rule event: %s", rule_name)
            return []

        eval_result = detail.get("newEvaluationResult") or {}
        compliance_type = eval_result.get("complianceType", "")

        if compliance_type == "NON_COMPLIANT":
            eval_qualifier = eval_result.get("evaluationResultIdentifier", {}).get("evaluationResultQualifier", {})
            raw_resource_id = eval_qualifier.get("resourceId", "Unknown-Resource")
            resource_type = eval_qualifier.get("resourceType", "AWS::Resource")
            timestamp = eval_result.get("resultRecordedTime", datetime.now(timezone.utc).isoformat())

            # Resolve IAM unique user ID (AIDA...) to username
            if resource_type == "AWS::IAM::User" and raw_resource_id.startswith("AIDA"):
                resolved_id = resolve_iam_username_from_config(raw_resource_id, client=cfg_client)
            else:
                resolved_id = raw_resource_id

            normalized_id = normalize_resource_id(resolved_id)
            mapping, control_key = find_control_mapping(rule_name=rule_name)

            severity = mapping["default_severity"]
            sla_info = SLA_MATRIX.get(severity, SLA_MATRIX["MEDIUM"])
            owner = assign_owner(mapping.get("risk_category", ""))

            finding_id = f"config-{rule_name}-{normalized_id}"
            parsed_findings.append({
                "CanonicalKey": f"{control_key}:{normalized_id}",
                "ControlKey": control_key,
                "Source": "AWS Config",
                "Sources": ["AWS Config"],
                "FindingID": finding_id,
                "Title": f"AWS Config Rule Failed: {rule_name}",
                "Description": f"Resource {normalized_id} violated compliance rule {rule_name}",
                "ResourceType": resource_type,
                "ResourceID": normalized_id,
                "RawResourceID": raw_resource_id,
                "Severity": severity,
                "RiskScore": sla_info["score"],
                "RemediationSLA_Days": sla_info["days"],
                "Owner": owner,
                "ControlMapping": mapping["ControlMapping"],
                "CIS_Match": mapping.get("CIS_Match", "closest"),
                "ISO_NIST_Basis": mapping.get("ISO_NIST_Basis", "analyst-assigned (indicative)"),
                "ISO_27001_2022": mapping["iso_27001_2022"],
                "NIST_CSF": mapping["nist_csf"],
                "CIS_AWS_Benchmark": mapping["cis_aws_benchmark"],
                "RiskCategory": mapping["risk_category"],
                "RemediationAction": mapping["remediation"],
                "Status": "OPEN",
                "LoggedTimestamp": str(timestamp),
                "Environment": ENVIRONMENT
            })
    except Exception as e:
        logger.error("Error parsing Config event: %s (detail: %s)", e, detail)

    return parsed_findings


def get_finding_hash(canonical_key: str) -> str:
    """Computes SHA256 hex digest for an idempotent S3 key."""
    return hashlib.sha256(canonical_key.encode("utf-8")).hexdigest()


def persist_individual_finding(bucket: str, finding: dict, client=None):
    """Writes an individual finding to S3 under findings/<sha256>.json."""
    c = client or s3_client
    if not c or not bucket:
        return

    sha = get_finding_hash(finding["CanonicalKey"])
    s3_key = f"findings/{sha}.json"

    # Merge existing Sources if already present
    existing_finding = None
    try:
        resp = c.get_object(Bucket=bucket, Key=s3_key)
        existing_finding = json.loads(resp["Body"].read().decode("utf-8"))
    except Exception:
        pass

    if existing_finding and isinstance(existing_finding, dict):
        existing_sources = set(existing_finding.get("Sources", [existing_finding.get("Source", "")]))
        new_sources = set(finding.get("Sources", [finding.get("Source", "")]))
        combined_sources = sorted(list(existing_sources.union(new_sources)))
        finding["Sources"] = combined_sources
        finding["Source"] = " / ".join(combined_sources)
        if existing_finding.get("LoggedTimestamp"):
            finding["LoggedTimestamp"] = min(existing_finding["LoggedTimestamp"], finding["LoggedTimestamp"])

    body = json.dumps(finding, indent=2)
    c.put_object(
        Bucket=bucket,
        Key=s3_key,
        Body=body.encode("utf-8"),
        ContentType="application/json"
    )
    logger.info("Persisted individual finding to s3://%s/%s", bucket, s3_key)


def rebuild_registers_from_findings_prefix(bucket: str, client=None) -> list:
    """
    Rebuilds risk_register.json and risk_register.csv by reading all individual
    objects under the findings/ prefix, deduplicating, and sorting by RiskScore descending.
    """
    c = client or s3_client
    if not c or not bucket:
        return []

    paginator = c.get_paginator("list_objects_v2")
    canonical_map = {}

    for page in paginator.paginate(Bucket=bucket, Prefix="findings/"):
        for item in page.get("Contents", []):
            key = item["Key"]
            if not key.endswith(".json"):
                continue
            try:
                resp = c.get_object(Bucket=bucket, Key=key)
                content = resp["Body"].read().decode("utf-8")
                finding_obj = json.loads(content)
                ckey = finding_obj.get("CanonicalKey", key)

                if ckey in canonical_map:
                    existing = canonical_map[ckey]
                    s1 = set(existing.get("Sources", [existing.get("Source", "")]))
                    s2 = set(finding_obj.get("Sources", [finding_obj.get("Source", "")]))
                    merged_sources = sorted(list(s1.union(s2)))
                    existing["Sources"] = merged_sources
                    existing["Source"] = " / ".join(merged_sources)
                else:
                    canonical_map[ckey] = finding_obj
            except Exception as err:
                logger.error("Failed to read finding object s3://%s/%s: %s", bucket, key, err)

    records = list(canonical_map.values())
    records.sort(key=lambda x: x.get("RiskScore", 0), reverse=True)

    # Rebuild JSON
    json_bytes = json.dumps(records, indent=2).encode("utf-8")
    c.put_object(
        Bucket=bucket,
        Key="risk_register.json",
        Body=json_bytes,
        ContentType="application/json"
    )

    # Rebuild CSV
    if records:
        out = io.StringIO()
        fieldnames = [
            "FindingID", "CanonicalKey", "ControlKey", "Source", "Title", "Description",
            "ResourceType", "ResourceID", "Severity", "RiskScore", "RemediationSLA_Days",
            "Owner", "ControlMapping", "CIS_Match", "ISO_NIST_Basis", "ISO_27001_2022",
            "NIST_CSF", "CIS_AWS_Benchmark", "RiskCategory", "RemediationAction",
            "Status", "LoggedTimestamp", "Environment"
        ]
        all_keys = list(records[0].keys())
        for k in all_keys:
            if k not in fieldnames and k != "Sources":
                fieldnames.append(k)

        writer = csv.DictWriter(out, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for r in records:
            writer.writerow(r)

        c.put_object(
            Bucket=bucket,
            Key="risk_register.csv",
            Body=out.getvalue().encode("utf-8"),
            ContentType="text/csv"
        )

    logger.info("Successfully rebuilt register from %d finding objects in s3://%s", len(records), bucket)
    return records


def lambda_handler(event, context, custom_s3_client=None, custom_config_client=None):
    """Main Lambda entrypoint triggered by EventBridge."""
    logger.info("Received EventBridge event: %s", json.dumps(event))

    active_s3 = custom_s3_client or s3_client
    active_config = custom_config_client or config_client
    source = event.get("source", "")
    detail = event.get("detail", {})
    new_findings = []

    if source == "aws.securityhub":
        new_findings = parse_security_hub_finding(detail)
    elif source == "aws.config":
        new_findings = parse_config_event(detail, cfg_client=active_config)
    else:
        if "findings" in detail:
            new_findings = parse_security_hub_finding(detail)
        elif "newEvaluationResult" in detail:
            new_findings = parse_config_event(detail, cfg_client=active_config)
        else:
            logger.warning("Unrecognized event source: %s", source)

    if not new_findings:
        logger.info("No actionable compliance failure findings to record.")
        return {"statusCode": 200, "message": "No non-compliant findings detected"}

    # Write each individual finding idempotently
    for finding in new_findings:
        persist_individual_finding(RISK_REGISTER_BUCKET, finding, client=active_s3)

    # Self-healing register rebuild from all findings objects in S3
    all_findings = rebuild_registers_from_findings_prefix(RISK_REGISTER_BUCKET, client=active_s3)

    return {
        "statusCode": 200,
        "processed_findings_count": len(new_findings),
        "total_register_entries": len(all_findings),
        "sample_finding": new_findings[0] if new_findings else None
    }


if __name__ == "__main__":
    print("[*] Risk Register Processor module loaded.")
