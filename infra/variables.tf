variable "subscription_id" {
  description = "Azure subscription ID to deploy into."
  type        = string
}

variable "location" {
  description = <<-DESC
    Azure region for the Foundry resource.
    Claude models deploy as Global Standard; eastus2 and swedencentral are
    reliable choices. Check region availability before changing this.
  DESC
  type        = string
  default     = "eastus2"
}

variable "resource_group_name" {
  description = "Resource group name. Created if it does not exist."
  type        = string
  default     = "rg-soc-triage-agent"
}

variable "project_name" {
  description = "Short name used to derive resource names. Lowercase alphanumeric."
  type        = string
  default     = "soctriage"

  validation {
    condition     = can(regex("^[a-z0-9]{3,12}$", var.project_name))
    error_message = "project_name must be 3-12 lowercase alphanumeric characters."
  }
}

variable "triage_model" {
  description = <<-DESC
    Primary triage model deployment.

    claude-sonnet-5 is the recommended default: GA hosted on Azure, 1M context,
    vision, adaptive thinking, and listed by Microsoft as suited to cybersecurity
    workloads. Claude models on Foundry require an Azure Marketplace subscription
    and bill through Claude Consumption Units (CCU).
  DESC
  type        = string
  default     = "claude-sonnet-5"
}

variable "triage_model_capacity" {
  description = "Capacity units for the triage deployment."
  type        = number
  default     = 1
}

variable "escalation_model" {
  description = "Model used for the second-pass review of high-severity findings."
  type        = string
  default     = "claude-opus-5"
}

variable "escalation_model_capacity" {
  description = "Capacity units for the escalation deployment."
  type        = number
  default     = 1
}

variable "deploy_claude_models" {
  description = <<-DESC
    Whether Terraform should create the Claude model deployments.

    Set this to false on the first apply if the subscription does not yet have the
    Anthropic Marketplace offer accepted — deployment will fail until it does.
    Accept the offer in the Foundry portal, then re-apply with this set to true.
  DESC
  type        = bool
  default     = true
}

variable "enable_app_insights" {
  description = "Deploy Application Insights for agent tracing."
  type        = bool
  default     = true
}

variable "analyst_principal_ids" {
  description = <<-DESC
    Entra object IDs of analysts who should be able to run the notebook.
    Each is granted Azure AI User on the Foundry resource. Find yours with:
      az ad signed-in-user show --query id -o tsv
  DESC
  type        = list(string)
  default     = []
}

variable "tags" {
  description = "Tags applied to all resources."
  type        = map(string)
  default = {
    workload    = "soc-email-triage-agent"
    environment = "demo"
    managed_by  = "terraform"
  }
}
