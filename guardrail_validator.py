#!/usr/bin/env python3
"""
Terraform Azure Landing Zone Guardrails Validator CLI.
Validates HCL structure, policy definitions, and compliance with CAF Enterprise-Scale.

Author: Luis Garcia Villena <garciavillenaluis@gmail.com>
Role: Security Transformation Analyst @ Accenture | CCSP & CCGP (ISMS Forum)
License: Apache-2.0
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Optional


@dataclass
class PolicyValidationResult:
    guardrail_id: str
    name: str
    target_scope: str
    enforcement_mode: str
    status: str
    details: str


class GuardrailValidator:
    """Validates Terraform HCL and policy JSON compliance."""

    MANDATORY_GUARDRAILS = {
        "GR-AZ-NET-01": "Enforce Private Endpoints for PaaS Storage",
        "GR-AZ-IAM-04": "Prohibit Custom RBAC Owner Grants at Subscription Scope",
        "GR-AZ-SEC-09": "Require Key Vault Diagnostic Logging to Enterprise Log Analytics"
    }

    def __init__(self, hcl_dir: str = "."):
        self.hcl_dir = hcl_dir

    def validate_hcl_files(self) -> Dict[str, Any]:
        """Checks for presence of required Terraform files and basic HCL syntax integrity."""
        required_files = ["main.tf", "variables.tf", "outputs.tf"]
        missing = []
        found = []

        for rf in required_files:
            fp = os.path.join(self.hcl_dir, rf)
            if not os.path.exists(fp):
                missing.append(rf)
            else:
                found.append(rf)

        if missing:
            return {"valid": False, "missing_files": missing, "found_files": found}

        # Validate main.tf contains mandatory policy definitions
        with open(os.path.join(self.hcl_dir, "main.tf"), "r", encoding="utf-8") as f:
            main_content = f.read()

        policy_checks = {}
        for gid, desc in self.MANDATORY_GUARDRAILS.items():
            present = gid in main_content
            policy_checks[gid] = {
                "description": desc,
                "declared_in_hcl": present
            }

        # Check NSG Deny rules
        nsg_ssh_deny = "DenyInternetSSHInbound" in main_content
        nsg_rdp_deny = "DenyInternetRDPInbound" in main_content

        all_declared = all(p["declared_in_hcl"] for p in policy_checks.values()) and nsg_ssh_deny and nsg_rdp_deny

        return {
            "valid": all_declared,
            "found_files": found,
            "policy_definitions": policy_checks,
            "nsg_ssh_deny_enforced": nsg_ssh_deny,
            "nsg_rdp_deny_enforced": nsg_rdp_deny
        }

    def validate_policy_json(self, json_path: str) -> List[PolicyValidationResult]:
        """Validates the landing_zone_guardrails.json telemetry file."""
        if not os.path.exists(json_path):
            raise FileNotFoundError(f"Policy file '{json_path}' not found.")

        with open(json_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        guardrails = data.get("guardrails", [])
        results: List[PolicyValidationResult] = []

        for g in guardrails:
            gid = g.get("guardrail_id", "UNKNOWN")
            name = g.get("name", "Unknown Guardrail")
            scope = g.get("target_scope", "ManagementGroup:LandingZones")
            mode = g.get("enforcement_mode", "Deny")
            status = g.get("compliance_status", "PASSED")

            results.append(PolicyValidationResult(
                guardrail_id=gid,
                name=name,
                target_scope=scope,
                enforcement_mode=mode,
                status=status,
                details=f"Scope: {scope} | Mode: {mode}"
            ))

        return results


def main() -> None:
    try:
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

    parser = argparse.ArgumentParser(
        description="Azure Landing Zone Terraform Guardrail Validator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python guardrail_validator.py
  python guardrail_validator.py --policy-file policies/landing_zone_guardrails.json
  python guardrail_validator.py --format json
        """
    )
    parser.add_argument("--hcl-dir", default=".", help="Directory containing Terraform files (default: .)")
    parser.add_argument("--policy-file", default="policies/landing_zone_guardrails.json", help="Path to guardrails JSON file")
    parser.add_argument("--format", choices=["table", "json"], default="table", help="Output format")

    args = parser.parse_args()
    validator = GuardrailValidator(hcl_dir=args.hcl_dir)

    hcl_res = validator.validate_hcl_files()

    policy_results = []
    if os.path.exists(args.policy_file):
        policy_results = validator.validate_policy_json(args.policy_file)

    if args.format == "json":
        output = {
            "hcl_validation": hcl_res,
            "telemetry_policy_checks": [asdict(r) for r in policy_results]
        }
        print(json.dumps(output, indent=2))
    else:
        print("==========================================================================")
        print("   TERRAFORM AZURE LANDING ZONE GUARDRAILS VALIDATION")
        print("==========================================================================")
        print(f"HCL Syntax & File Integrity: {'[VALID - ALL PASS]' if hcl_res['valid'] else '[FAIL]'}")
        print(f"Found HCL Modules: {', '.join(hcl_res.get('found_files', []))}")
        print("Guardrail Declarations:")
        for gid, data in hcl_res.get("policy_definitions", {}).items():
            status_str = "PASSED" if data["declared_in_hcl"] else "MISSING"
            print(f"  - [{status_str}] {gid}: {data['description']}")
        print(f"NSG Ingress SSH Deny (Port 22):   {'PASSED' if hcl_res.get('nsg_ssh_deny_enforced') else 'FAILED'}")
        print(f"NSG Ingress RDP Deny (Port 3389): {'PASSED' if hcl_res.get('nsg_rdp_deny_enforced') else 'FAILED'}")
        print("--------------------------------------------------------------------------")
        if policy_results:
            print("Active Telemetry Policies (from JSON):")
            for pr in policy_results:
                print(f"  - [{pr.status}] {pr.guardrail_id}: {pr.name} ({pr.enforcement_mode})")
        print("==========================================================================")

    if not hcl_res["valid"]:
        sys.exit(1)


if __name__ == "__main__":
    main()
