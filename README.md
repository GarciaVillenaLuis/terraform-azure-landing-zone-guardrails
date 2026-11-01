# Terraform Azure Landing Zone Guardrails 🛡️

Automated **Policy-as-Code (PaC)** guardrails and Terraform compliance validations for enterprise **Microsoft Azure Landing Zones** based on the **Cloud Adoption Framework (CAF)**.

## Core Capabilities
- **Management Group Hierarchy Enforcement**: Validates subscription placement and custom Azure Policy assignments.
- **Network Security Perimeter Checks**: Ensures private endpoints, DDoS protection, and NSG baseline conformance.
- **Automated Drift Detection**: Policy compliance signatures tracked in [`policies/landing_zone_guardrails.json`](./policies/landing_zone_guardrails.json).
