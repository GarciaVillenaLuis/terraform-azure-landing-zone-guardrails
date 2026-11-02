#!/usr/bin/env python3
"""
Unit tests for Terraform Azure Landing Zone Guardrail Validator.
"""

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from guardrail_validator import GuardrailValidator


class TestGuardrailValidator(unittest.TestCase):
    def setUp(self):
        self.repo_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        self.validator = GuardrailValidator(hcl_dir=self.repo_dir)

    def test_hcl_files_exist_and_valid(self):
        res = self.validator.validate_hcl_files()
        self.assertTrue(res["valid"])
        self.assertIn("main.tf", res["found_files"])
        self.assertIn("variables.tf", res["found_files"])
        self.assertIn("outputs.tf", res["found_files"])
        self.assertTrue(res["nsg_ssh_deny_enforced"])
        self.assertTrue(res["nsg_rdp_deny_enforced"])

    def test_mandatory_policies_present(self):
        res = self.validator.validate_hcl_files()
        policy_defs = res["policy_definitions"]
        self.assertTrue(policy_defs["GR-AZ-NET-01"]["declared_in_hcl"])
        self.assertTrue(policy_defs["GR-AZ-IAM-04"]["declared_in_hcl"])
        self.assertTrue(policy_defs["GR-AZ-SEC-09"]["declared_in_hcl"])

    def test_validate_policy_json(self):
        sample_json = {
            "guardrails": [
                {
                    "guardrail_id": "GR-AZ-NET-01",
                    "name": "Enforce Private Endpoints",
                    "target_scope": "ManagementGroup:LandingZones",
                    "enforcement_mode": "Deny",
                    "compliance_status": "PASSED"
                }
            ]
        }
        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".json", encoding="utf-8") as f:
            json.dump(sample_json, f)
            temp_path = f.name

        try:
            results = self.validator.validate_policy_json(temp_path)
            self.assertEqual(len(results), 1)
            self.assertEqual(results[0].guardrail_id, "GR-AZ-NET-01")
            self.assertEqual(results[0].status, "PASSED")
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)

    def test_policy_assignments_declared(self):
        main_tf = os.path.join(self.repo_dir, "main.tf")
        with open(main_tf, "r", encoding="utf-8") as f:
            content = f.read()
        self.assertIn("assign_deny_storage_public", content)
        self.assertIn("assign_prohibit_custom_owner", content)
        self.assertIn("assign_require_keyvault_audit", content)

    def test_existing_policy_json_file(self):
        policy_file = os.path.join(self.repo_dir, "policies", "landing_zone_guardrails.json")
        if os.path.exists(policy_file):
            results = self.validator.validate_policy_json(policy_file)
            self.assertEqual(len(results), 3)
            ids = {r.guardrail_id for r in results}
            self.assertIn("GR-AZ-NET-01", ids)
            self.assertIn("GR-AZ-IAM-04", ids)
            self.assertIn("GR-AZ-SEC-09", ids)


if __name__ == "__main__":
    unittest.main()
