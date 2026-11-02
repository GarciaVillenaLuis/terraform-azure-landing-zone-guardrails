/**
 * Terraform Azure Landing Zone Guardrails - Input Variables
 * Aligned with Microsoft Cloud Adoption Framework (CAF) Enterprise-Scale
 * 
 * Author: Luis Garcia Villena <garciavillenaluis@gmail.com>
 * Role: Security Transformation Analyst @ Accenture | CCSP & CCGP (ISMS Forum)
 */

variable "environment" {
  type        = string
  description = "Target deployment environment tier (prod, stage, dev)."
  default     = "prod"

  validation {
    condition     = contains(["prod", "stage", "dev"], var.environment)
    error_message = "The environment must be one of: prod, stage, dev."
  }
}

variable "prefix" {
  type        = string
  description = "Standard naming prefix for all Landing Zone governance resources."
  default     = "alz-sec"

  validation {
    condition     = length(var.prefix) >= 3 && length(var.prefix) <= 12
    error_message = "Prefix length must be between 3 and 12 characters."
  }
}

variable "location" {
  type        = string
  description = "Primary Azure region for Landing Zone infrastructure."
  default     = "westeurope"

  validation {
    condition     = contains(["westeurope", "northeurope", "spaincentral", "francecentral"], var.location)
    error_message = "Region must be an approved European deployment region."
  }
}

variable "policy_enforcement_mode" {
  type        = string
  description = "Policy enforcement mode: 'Default' (active deny/audit) or 'DoNotEnforce' (testing only)."
  default     = "Default"

  validation {
    condition     = contains(["Default", "DoNotEnforce"], var.policy_enforcement_mode)
    error_message = "Enforcement mode must be either 'Default' or 'DoNotEnforce'."
  }
}

variable "log_analytics_retention_in_days" {
  type        = number
  description = "Retention period for centralized security audit logs in Log Analytics."
  default     = 365

  validation {
    condition     = var.log_analytics_retention_in_days >= 90 && var.log_analytics_retention_in_days <= 730
    error_message = "Log retention must satisfy compliance minimum of 90 days and maximum 730 days."
  }
}

variable "tags" {
  type        = map(string)
  description = "Mandatory governance metadata tags applied to all Landing Zone assets."
  default = {
    "Architecture"        = "Azure-CAF-Enterprise-Scale"
    "ManagedBy"           = "Terraform"
    "SecurityLevel"       = "MissionCritical"
    "DataClassification"  = "Restricted"
    "Owner"               = "Luis Garcia Villena"
  }
}
