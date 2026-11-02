# Terraform Azure Landing Zone Guardrails 🛡️

[![Terraform Version](https://img.shields.io/badge/Terraform-%3E%3D%201.5.0-623ce4?style=flat-square&logo=terraform&logoColor=white)](https://www.terraform.io/)
[![Azure Provider](https://img.shields.io/badge/azurerm-v3.90.0-0078d4?style=flat-square&logo=microsoftazure&logoColor=white)](https://registry.terraform.io/providers/hashicorp/azurerm/latest)
[![Policy Status](https://img.shields.io/badge/Guardrails-Enforced%20(Deny)-success?style=flat-square&logo=azureartifacts&logoColor=white)](https://github.com/GarciaVillenaLuis/terraform-azure-landing-zone-guardrails)
[![License](https://img.shields.io/badge/License-Apache%202.0-green?style=flat-square)](LICENSE)
[![Framework](https://img.shields.io/badge/Architecture-Azure%20CAF%20Enterprise--Scale-blue?style=flat-square)](https://learn.microsoft.com/azure/cloud-adoption-framework/)

Automated **Policy-as-Code (PaC)** guardrails and Terraform compliance validations for enterprise **Microsoft Azure Landing Zones** based on the **Cloud Adoption Framework (CAF)**.

Architected and maintained by **Luis García Villena** (*Security Transformation Analyst @ Accenture | CCSP® & CCGP ISMS Forum*).

---

## 🏛️ Architecture & Governance Hierarchy

This blueprint deploys a resilient enterprise-scale hierarchy in accordance with Microsoft CAF:

```text
                     [ Root Tenant Management Group ]
                                    │
                    [ alz-sec-root Management Group ]
                                    │
                    [ alz-sec-landing-zones (MG) ]
                      │                        │
             [ Online Workloads ]      [ Corp Workloads ]
                      │                        │
       (PaC Guardrails: Deny Public Storage, Prohibit Custom Owner, Require Audit Logs)
```

### Deployed Security Guardrails
1. **`GR-AZ-NET-01`**: **Deny Public Network Access on Storage Accounts**  
   Forces all storage endpoints behind private link endpoints; blocks unencrypted public blob access.
2. **`GR-AZ-IAM-04`**: **Prohibit Custom RBAC Owner Grants at Subscription Scope**  
   Precludes privilege escalation via custom roles granting wildcard `*` permissions at subscription or root scopes.
3. **`GR-AZ-SEC-09`**: **Require Key Vault Diagnostic Logging to Log Analytics**  
   Ensures cryptographically tamper-evident event streaming (`AuditEvent`) to the central governance Log Analytics workspace.
4. **Hardened Baseline NSG**:  
   Denies inbound TCP port 22 (SSH) and 3389 (RDP) from public internet (`Internet` source prefix).

---

## 📦 Terraform Files & Modules

- **`main.tf`**: Core resources, CAF Management Groups, Custom Azure Policy Definitions, Management Group Policy Assignments, Log Analytics Workspace, and Baseline NSG.
- **`variables.tf`**: Input parameters with built-in validation constraints for environment tiers (`prod`, `stage`, `dev`), regions, and retention windows.
- **`outputs.tf`**: Structured IDs, resource references, and compliance posture summaries.
- **`guardrail_validator.py`**: Autonomous CLI validation tool for automated CI/CD PR checks.

---

## 🚀 Deployment Instructions

### Prerequisites
- Terraform $\ge 1.5.0$
- Azure CLI authenticated with `Owner` or `User Access Administrator` permissions on Root MG

### Initialize and Plan
```bash
terraform init
terraform plan -var="environment=prod" -var="location=westeurope" -out=tfplan
```

### Apply Governance Guardrails
```bash
terraform apply tfplan
```

---

## 🔍 Guardrail Validator CLI

Validate Terraform HCL and policy conformity locally or in CI/CD pipelines:

```bash
python guardrail_validator.py --hcl-dir . --policy-file policies/landing_zone_guardrails.json
```

**Sample Output:**
```text
==========================================================================
   TERRAFORM AZURE LANDING ZONE GUARDRAILS VALIDATION
==========================================================================
HCL Syntax & File Integrity: [VALID - ALL PASS]
Found HCL Modules: main.tf, variables.tf, outputs.tf
Guardrail Declarations:
  • [PASSED] GR-AZ-NET-01: Enforce Private Endpoints for PaaS Storage
  • [PASSED] GR-AZ-IAM-04: Prohibit Custom RBAC Owner Grants at Subscription Scope
  • [PASSED] GR-AZ-SEC-09: Require Key Vault Diagnostic Logging to Enterprise Log Analytics
NSG Ingress SSH Deny (Port 22):   PASSED
NSG Ingress RDP Deny (Port 3389): PASSED
--------------------------------------------------------------------------
Active Telemetry Policies (from JSON):
  - [PASSED] GR-AZ-NET-01: Enforce Private Endpoints for PaaS Storage (Deny)
  - [PASSED] GR-AZ-IAM-04: Prohibit Custom RBAC Owner Grants at Subscription Scope (Deny)
  - [PASSED] GR-AZ-SEC-09: Require Key Vault Diagnostic Logging to Enterprise Log Analytics (AuditIfNotExists)
==========================================================================
```

---

## 🧪 Unit Testing

Execute automated unit tests:

```bash
python -m unittest tests/test_guardrails.py
```

---

## 📜 Active Telemetry & Guardrail Ledger

Active guardrail rules and compliance signatures are tracked in:
- [`policies/landing_zone_guardrails.json`](./policies/landing_zone_guardrails.json)
