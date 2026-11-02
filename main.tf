/**
 * Microsoft Azure Landing Zone Guardrails & Policy-as-Code Engine
 * Implements CAF Enterprise-Scale Architecture and CIS Azure Foundations Controls
 *
 * Author: Luis Garcia Villena <garciavillenaluis@gmail.com>
 * Role: Security Transformation Analyst @ Accenture | CCSP & CCGP (ISMS Forum)
 */

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.90.0"
    }
  }
}

provider "azurerm" {
  features {
    key_vault {
      purge_protection_enabled                        = true
      recover_soft_deleted_key_vaults                 = true
      soft_delete_retention_days                      = 90
    }
    resource_group {
      prevent_deletion_if_contains_resources          = true
    }
  }
}

# -----------------------------------------------------------------------------
# 1. MANAGEMENT GROUP HIERARCHY (CAF ENTERPRISE-SCALE)
# -----------------------------------------------------------------------------

resource "azurerm_management_group" "mg_root_security" {
  display_name               = "${var.prefix}-root"
  name                       = "${var.prefix}-root-mg"
  subscription_ids           = []
}

resource "azurerm_management_group" "mg_landing_zones" {
  display_name               = "${var.prefix}-landing-zones"
  name                       = "${var.prefix}-lz-mg"
  parent_management_group_id = azurerm_management_group.mg_root_security.id
}

# -----------------------------------------------------------------------------
# 2. POLICY-AS-CODE GUARDRAILS (AZURE POLICY DEFINITIONS)
# -----------------------------------------------------------------------------

# Guardrail 1: Enforce Private Endpoints for PaaS Storage (GR-AZ-NET-01)
resource "azurerm_policy_definition" "deny_storage_public_access" {
  name         = "gr-az-net-01-deny-storage-public"
  policy_type  = "Custom"
  mode         = "Indexed"
  display_name = "[GR-AZ-NET-01] Deny Public Network Access on Storage Accounts"
  description  = "Enforces zero public ingress by requiring private endpoints for all storage accounts within Landing Zones."

  management_group_id = azurerm_management_group.mg_root_security.id

  metadata = jsonencode({
    category = "Security Guardrails"
    version  = "2.1.0"
    author   = "Luis Garcia Villena"
  })

  policy_rule = jsonencode({
    if = {
      allOf = [
        {
          field  = "type"
          equals = "Microsoft.Storage/storageAccounts"
        },
        {
          field  = "Microsoft.Storage/storageAccounts/publicNetworkAccess"
          notequals = "Disabled"
        }
      ]
    }
    then = {
      effect = "Deny"
    }
  })
}

# Guardrail 2: Prohibit Custom RBAC Owner Grants at Subscription Scope (GR-AZ-IAM-04)
resource "azurerm_policy_definition" "prohibit_custom_owner_roles" {
  name         = "gr-az-iam-04-prohibit-owner-grants"
  policy_type  = "Custom"
  mode         = "All"
  display_name = "[GR-AZ-IAM-04] Prohibit Custom RBAC Owner Grants at Subscription Scope"
  description  = "Blocks creation of custom RBAC roles with wildcard administrative ownership (* permissions) at subscription roots."

  management_group_id = azurerm_management_group.mg_root_security.id

  metadata = jsonencode({
    category = "IAM Governance"
    version  = "1.4.0"
    author   = "Luis Garcia Villena"
  })

  policy_rule = jsonencode({
    if = {
      allOf = [
        {
          field  = "type"
          equals = "Microsoft.Authorization/roleDefinitions"
        },
        {
          field  = "Microsoft.Authorization/roleDefinitions/permissions[*].actions[*]"
          contains = "*"
        }
      ]
    }
    then = {
      effect = "Deny"
    }
  })
}

# Guardrail 3: Require Key Vault Diagnostic Logging to Log Analytics (GR-AZ-SEC-09)
resource "azurerm_policy_definition" "require_keyvault_audit_logs" {
  name         = "gr-az-sec-09-kv-audit-logging"
  policy_type  = "Custom"
  mode         = "Indexed"
  display_name = "[GR-AZ-SEC-09] Require Key Vault Audit Diagnostic Logging"
  description  = "Audits or denies Key Vault deployments lacking centralized audit logging routed to Log Analytics Workspace."

  management_group_id = azurerm_management_group.mg_root_security.id

  metadata = jsonencode({
    category = "Audit & Observability"
    version  = "1.2.0"
    author   = "Luis Garcia Villena"
  })

  policy_rule = jsonencode({
    if = {
      field  = "type"
      equals = "Microsoft.KeyVault/vaults"
    }
    then = {
      effect = "AuditIfNotExists"
      details = {
        type = "Microsoft.Insights/diagnosticSettings"
        existenceCondition = {
          allOf = [
            {
              field  = "Microsoft.Insights/diagnosticSettings/logs[*].enabled"
              equals = "true"
            },
            {
              field  = "Microsoft.Insights/diagnosticSettings/workspaceId"
              exists = "true"
            }
          ]
        }
      }
    }
  })
}

# -----------------------------------------------------------------------------
# 3. POLICY ASSIGNMENTS AT MANAGEMENT GROUP SCOPE
# -----------------------------------------------------------------------------

resource "azurerm_management_group_policy_assignment" "assign_deny_storage_public" {
  name                 = "assign-deny-storage-public"
  display_name         = "Enforce Deny Public Storage Access on Landing Zones"
  management_group_id  = azurerm_management_group.mg_landing_zones.id
  policy_definition_id = azurerm_policy_definition.deny_storage_public_access.id
  enforce              = var.policy_enforcement_mode == "Default"
}

resource "azurerm_management_group_policy_assignment" "assign_prohibit_custom_owner" {
  name                 = "assign-prohibit-owner-grants"
  display_name         = "Enforce Prohibit Owner Wildcards on Root MG"
  management_group_id  = azurerm_management_group.mg_root_security.id
  policy_definition_id = azurerm_policy_definition.prohibit_custom_owner_roles.id
  enforce              = var.policy_enforcement_mode == "Default"
}

resource "azurerm_management_group_policy_assignment" "assign_require_keyvault_audit" {
  name                 = "assign-require-kv-audit"
  display_name         = "Enforce Key Vault Diagnostic Logging on Landing Zones"
  management_group_id  = azurerm_management_group.mg_landing_zones.id
  policy_definition_id = azurerm_policy_definition.require_keyvault_audit_logs.id
  enforce              = var.policy_enforcement_mode == "Default"
}

# -----------------------------------------------------------------------------
# 4. REFERENCE HARDENED CORE INFRASTRUCTURE MODULE
# -----------------------------------------------------------------------------

resource "azurerm_resource_group" "rg_governance_core" {
  name     = "${var.prefix}-core-${var.environment}-rg"
  location = var.location
  tags     = var.tags
}

resource "azurerm_log_analytics_workspace" "law_central_security" {
  name                = "${var.prefix}-law-${var.environment}"
  location            = azurerm_resource_group.rg_governance_core.location
  resource_group_name = azurerm_resource_group.rg_governance_core.name
  sku                 = "PerGB2018"
  retention_in_days   = var.log_analytics_retention_in_days
  tags                = var.tags
}

resource "azurerm_network_security_group" "nsg_landing_zone_baseline" {
  name                = "${var.prefix}-baseline-${var.environment}-nsg"
  location            = azurerm_resource_group.rg_governance_core.location
  resource_group_name = azurerm_resource_group.rg_governance_core.name
  tags                = var.tags

  security_rule {
    name                       = "DenyInternetSSHInbound"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Deny"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "22"
    source_address_prefix      = "Internet"
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "DenyInternetRDPInbound"
    priority                   = 110
    direction                  = "Inbound"
    access                     = "Deny"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "3389"
    source_address_prefix      = "Internet"
    destination_address_prefix = "*"
  }
}
