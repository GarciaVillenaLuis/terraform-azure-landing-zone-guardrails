/**
 * Terraform Azure Landing Zone Guardrails - Outputs
 * 
 * Author: Luis Garcia Villena <garciavillenaluis@gmail.com>
 * Role: Security Transformation Analyst @ Accenture | CCSP & CCGP (ISMS Forum)
 */

output "root_management_group_id" {
  description = "Resource ID of the Root Security Management Group."
  value       = azurerm_management_group.mg_root_security.id
}

output "landing_zones_management_group_id" {
  description = "Resource ID of the Landing Zones Management Group."
  value       = azurerm_management_group.mg_landing_zones.id
}

output "policy_definition_deny_storage_public_id" {
  description = "Policy Definition ID for GR-AZ-NET-01 (Deny Storage Public Access)."
  value       = azurerm_policy_definition.deny_storage_public_access.id
}

output "policy_definition_prohibit_custom_owner_id" {
  description = "Policy Definition ID for GR-AZ-IAM-04 (Prohibit Custom Owner RBAC)."
  value       = azurerm_policy_definition.prohibit_custom_owner_roles.id
}

output "policy_definition_require_keyvault_audit_id" {
  description = "Policy Definition ID for GR-AZ-SEC-09 (Require Key Vault Audit Logging)."
  value       = azurerm_policy_definition.require_keyvault_audit_logs.id
}

output "policy_assignment_ids" {
  description = "IDs of Management Group policy assignments enforcing landing zone guardrails."
  value = {
    deny_storage_public_access = azurerm_management_group_policy_assignment.assign_deny_storage_public.id
    prohibit_custom_owner      = azurerm_management_group_policy_assignment.assign_prohibit_custom_owner.id
    require_keyvault_audit     = azurerm_management_group_policy_assignment.assign_require_keyvault_audit.id
  }
}

output "central_log_analytics_workspace_id" {
  description = "Resource ID of the centralized enterprise security Log Analytics Workspace."
  value       = azurerm_log_analytics_workspace.law_central_security.id
}

output "baseline_network_security_group_id" {
  description = "Resource ID of the baseline hardened Network Security Group."
  value       = azurerm_network_security_group.nsg_landing_zone_baseline.id
}

output "guardrails_compliance_summary" {
  description = "Summary of active Azure Policy-as-Code guardrail rules deployed."
  value = {
    framework          = "Azure Cloud Adoption Framework (CAF) Enterprise-Scale"
    active_guardrails  = 3
    enforcement_mode   = var.policy_enforcement_mode
    logging_workspace  = azurerm_log_analytics_workspace.law_central_security.name
    compliance_target  = "100% Policy Conformity"
  }
}
