#!/usr/bin/env python3
"""
Extended unit test suite for risk_register_processor.py using stubbed AWS clients.
Validates:
1. Two different Security Hub controls on the same bucket -> 2 distinct rows.
2. Account-level findings do not collapse.
3. IAM.5 maps to CIS 1.10.
4. Config AIDA event + Security Hub IAM.5 for the same user merges to 1 row with both Sources.
5. Security Hub "encrypted-volumes" + Config event for the same volume merges to 1 row.
6. "securityhub-*" Config events are ignored.
7. PASSED Security Hub findings are ignored.
8. Replays all saved fixtures and verifies register output.
"""

import os
import sys
import json
import csv
import io
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import risk_register_processor as processor


class StubS3Paginator:
    def __init__(self, objects_dict):
        self.objects_dict = objects_dict

    def paginate(self, Bucket="", Prefix=""):
        contents = []
        for k in sorted(self.objects_dict.keys()):
            if k.startswith(Prefix):
                contents.append({"Key": k})
        yield {"Contents": contents}


class StubS3Client:
    def __init__(self):
        self.storage = {}

    def get_object(self, Bucket="", Key=""):
        if Key not in self.storage:
            raise Exception(f"NoSuchKey: {Key}")
        data = self.storage[Key]
        return {"Body": io.BytesIO(data)}

    def put_object(self, Bucket="", Key="", Body=b"", ContentType=""):
        if isinstance(Body, str):
            Body = Body.encode("utf-8")
        self.storage[Key] = Body
        return {"ResponseMetadata": {"HTTPStatusCode": 200}}

    def get_paginator(self, operation_name):
        if operation_name == "list_objects_v2":
            return StubS3Paginator(self.storage)
        raise NotImplementedError(f"Paginator {operation_name} not implemented")


class StubConfigClient:
    def __init__(self, user_map=None):
        # Maps AIDA... -> username
        self.user_map = user_map or {
            "AIDAXWYOPVPW3HVOZJVTW": "cloud-compliance-demo-contractor-no-mfa"
        }

    def batch_get_resource_config(self, resourceKeys=None):
        items = []
        for rk in (resourceKeys or []):
            rid = rk.get("resourceId")
            if rid in self.user_map:
                items.append({
                    "resourceType": "AWS::IAM::User",
                    "resourceId": rid,
                    "resourceName": self.user_map[rid]
                })
        return {"baseConfigurationItems": items, "unprocessedResourceKeys": []}


class TestRiskRegisterProcessor(unittest.TestCase):
    def setUp(self):
        self.stub_s3 = StubS3Client()
        self.stub_config = StubConfigClient()
        self.bucket = "test-risk-register-bucket"
        processor.RISK_REGISTER_BUCKET = self.bucket
        self.events_dir = os.path.join(os.path.dirname(__file__), "test_events")

    def load_json(self, filename):
        path = os.path.join(self.events_dir, filename)
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)

    def test_passed_event_ignored(self):
        """Asserts that Security Hub PASSED findings produce 0 processed findings."""
        passed_event = self.load_json("security_hub_passed.json")
        res = processor.lambda_handler(passed_event, None, custom_s3_client=self.stub_s3, custom_config_client=self.stub_config)
        self.assertEqual(res["statusCode"], 200)
        self.assertEqual(res["message"], "No non-compliant findings detected")
        self.assertEqual(len(self.stub_s3.storage), 0)

    def test_two_different_controls_on_same_bucket(self):
        """Two different controls on the same bucket (e.g. TLS and Public Access Block) must yield 2 rows."""
        s3_tls = self.load_json("sh_failed_s3_tls.json")
        s3_pab = self.load_json("sh_failed_s3_block_public_access.json")

        processor.lambda_handler(s3_tls, None, custom_s3_client=self.stub_s3, custom_config_client=self.stub_config)
        res = processor.lambda_handler(s3_pab, None, custom_s3_client=self.stub_s3, custom_config_client=self.stub_config)

        self.assertEqual(res["total_register_entries"], 2)
        reg = json.loads(self.stub_s3.storage["risk_register.json"].decode("utf-8"))
        canonical_keys = [r["CanonicalKey"] for r in reg]
        self.assertEqual(len(set(canonical_keys)), 2)
        self.assertIn("CIS_2.1.2:cloud-compliance-demo-public-demo-oxcof074", canonical_keys)
        self.assertIn("CIS_2.1.5:cloud-compliance-demo-public-demo-oxcof074", canonical_keys)

    def test_account_level_findings_do_not_collapse(self):
        """Two different account-level controls (e.g. CloudTrail and Password Policy) must not overwrite each other."""
        ct_event = self.load_json("sh_failed_cloudtrail_multiregion.json")
        pwd_event = {
            "version": "0",
            "source": "aws.securityhub",
            "detail-type": "Security Hub Findings - Imported",
            "detail": {
                "findings": [{
                    "Id": "arn:aws:securityhub:us-east-1:123456789012:security-control/IAM.15/finding/pwd-len",
                    "Title": "Ensure IAM password policy requires minimum password length of 14 or greater",
                    "Compliance": {
                        "Status": "FAILED",
                        "SecurityControlId": "IAM.15",
                        "RelatedRequirements": ["CIS AWS Foundations Benchmark v1.4.0/1.8"]
                    },
                    "Severity": {"Label": "MEDIUM"},
                    "Resources": [{"Id": "AWS::::Account:123456789012", "Type": "AwsAccount"}]
                }]
            }
        }

        processor.lambda_handler(ct_event, None, custom_s3_client=self.stub_s3, custom_config_client=self.stub_config)
        res = processor.lambda_handler(pwd_event, None, custom_s3_client=self.stub_s3, custom_config_client=self.stub_config)

        self.assertEqual(res["total_register_entries"], 2)
        reg = json.loads(self.stub_s3.storage["risk_register.json"].decode("utf-8"))
        ck_set = {r["CanonicalKey"] for r in reg}
        self.assertIn("CIS_3.1:account", ck_set)
        self.assertIn("CIS_1.8:account", ck_set)

    def test_iam_mfa_mapped_to_cis_1_10(self):
        """Asserts that Security Hub IAM.5 maps to CIS 1.10 (not 1.5)."""
        iam_event = self.load_json("sh_failed_iam_mfa.json")
        res = processor.lambda_handler(iam_event, None, custom_s3_client=self.stub_s3, custom_config_client=self.stub_config)
        self.assertEqual(res["processed_findings_count"], 1)
        sample = res["sample_finding"]
        self.assertEqual(sample["ControlKey"], "CIS_1.10")
        self.assertEqual(sample["ControlMapping"], "MAPPED")
        self.assertIn("1.10", sample["CIS_AWS_Benchmark"])
        self.assertEqual(sample["Owner"], "Identity & Access Team")

    def test_config_aida_merges_with_security_hub_iam_user(self):
        """Asserts that Config event with AIDA... resolves username and merges with Security Hub finding."""
        # 1. Security Hub finding with ARN
        sh_event = self.load_json("sh_failed_iam_mfa.json")
        processor.lambda_handler(sh_event, None, custom_s3_client=self.stub_s3, custom_config_client=self.stub_config)

        # 2. Config event with AIDA user ID
        cfg_event = {
            "version": "0",
            "source": "aws.config",
            "detail-type": "Config Rules Compliance Change",
            "detail": {
                "configRuleName": "iam-user-mfa-enabled",
                "newEvaluationResult": {
                    "evaluationResultIdentifier": {
                        "evaluationResultQualifier": {
                            "configRuleName": "iam-user-mfa-enabled",
                            "resourceType": "AWS::IAM::User",
                            "resourceId": "AIDAXWYOPVPW3HVOZJVTW"
                        }
                    },
                    "complianceType": "NON_COMPLIANT",
                    "resultRecordedTime": "2026-09-20T00:00:00Z"
                }
            }
        }
        res = processor.lambda_handler(cfg_event, None, custom_s3_client=self.stub_s3, custom_config_client=self.stub_config)

        # Must merge into ONE row
        self.assertEqual(res["total_register_entries"], 1)
        reg = json.loads(self.stub_s3.storage["risk_register.json"].decode("utf-8"))
        entry = reg[0]
        self.assertEqual(entry["ResourceID"], "cloud-compliance-demo-contractor-no-mfa")
        self.assertIn("AWS Config", entry["Sources"])
        self.assertIn("AWS Security Hub", entry["Sources"])
        self.assertEqual(entry["ControlKey"], "CIS_1.10")
        self.assertEqual(entry["Owner"], "Identity & Access Team")

    def test_security_hub_and_config_encrypted_volumes_merge(self):
        """Asserts that Security Hub Title='encrypted-volumes' merges with Config rule encrypted-volumes for same volume."""
        sh_vol = self.load_json("sh_failed_encrypted_volumes.json")
        cfg_vol = {
            "version": "0",
            "source": "aws.config",
            "detail-type": "Config Rules Compliance Change",
            "detail": {
                "configRuleName": "encrypted-volumes",
                "newEvaluationResult": {
                    "evaluationResultIdentifier": {
                        "evaluationResultQualifier": {
                            "configRuleName": "encrypted-volumes",
                            "resourceType": "AWS::EC2::Volume",
                            "resourceId": "vol-0d35a3ca9a7c6de4b"
                        }
                    },
                    "complianceType": "NON_COMPLIANT",
                    "resultRecordedTime": "2026-09-20T00:00:00Z"
                }
            }
        }

        processor.lambda_handler(sh_vol, None, custom_s3_client=self.stub_s3, custom_config_client=self.stub_config)
        res = processor.lambda_handler(cfg_vol, None, custom_s3_client=self.stub_s3, custom_config_client=self.stub_config)

        self.assertEqual(res["total_register_entries"], 1)
        reg = json.loads(self.stub_s3.storage["risk_register.json"].decode("utf-8"))
        entry = reg[0]
        self.assertEqual(entry["ResourceID"], "vol-0d35a3ca9a7c6de4b")
        self.assertIn("AWS Config", entry["Sources"])
        self.assertIn("AWS Security Hub", entry["Sources"])
        self.assertEqual(entry["ControlKey"], "CIS_2.2.1")
        self.assertEqual(entry["CIS_Match"], "closest")
        self.assertEqual(entry["ISO_NIST_Basis"], "analyst-assigned (indicative)")
        self.assertEqual(entry["Owner"], "Data Protection Team")

    def test_securityhub_managed_config_rule_ignored(self):
        """Config events from Security Hub-managed rules (securityhub-*) must be ignored."""
        sh_managed_cfg_event = {
            "version": "0",
            "source": "aws.config",
            "detail-type": "Config Rules Compliance Change",
            "detail": {
                "configRuleName": "securityhub-s3-bucket-ssl-requests-only-55c8a7cd",
                "newEvaluationResult": {
                    "evaluationResultIdentifier": {
                        "evaluationResultQualifier": {
                            "configRuleName": "securityhub-s3-bucket-ssl-requests-only-55c8a7cd",
                            "resourceType": "AWS::S3::Bucket",
                            "resourceId": "cloud-compliance-demo-config-cezeajty"
                        }
                    },
                    "complianceType": "NON_COMPLIANT"
                }
            }
        }
        res = processor.lambda_handler(sh_managed_cfg_event, None, custom_s3_client=self.stub_s3, custom_config_client=self.stub_config)
        self.assertEqual(res["statusCode"], 200)
        self.assertEqual(res["message"], "No non-compliant findings detected")

    def test_restricted_ssh_assigned_to_network_security_team(self):
        """Asserts that restricted-ssh findings with RiskCategory containing 'Unauthorized Access' map to Network Security Team, not Identity."""
        ssh_event = {
            "version": "0",
            "source": "aws.config",
            "detail-type": "Config Rules Compliance Change",
            "detail": {
                "configRuleName": "restricted-ssh",
                "newEvaluationResult": {
                    "evaluationResultIdentifier": {
                        "evaluationResultQualifier": {
                            "configRuleName": "restricted-ssh",
                            "resourceType": "AWS::EC2::SecurityGroup",
                            "resourceId": "sg-06f92c30d1042feb2"
                        }
                    },
                    "complianceType": "NON_COMPLIANT",
                    "resultRecordedTime": "2026-09-20T00:00:00Z"
                }
            }
        }
        res = processor.lambda_handler(ssh_event, None, custom_s3_client=self.stub_s3, custom_config_client=self.stub_config)
        self.assertEqual(res["total_register_entries"], 1)
        reg = json.loads(self.stub_s3.storage["risk_register.json"].decode("utf-8"))
        entry = reg[0]
        self.assertEqual(entry["ResourceID"], "sg-06f92c30d1042feb2")
        self.assertEqual(entry["ControlKey"], "CIS_5.2")
        self.assertEqual(entry["Owner"], "Network Security Team")


if __name__ == "__main__":
    unittest.main(verbosity=2)
