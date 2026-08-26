## Random suffix keeps globally-unique names (custom subdomain) collision-free.
resource "random_string" "suffix" {
  length  = 5
  numeric = true
  special = false
  upper   = false
  lower   = true
}

locals {
  foundry_name = "${var.project_name}${random_string.suffix.result}"
}

resource "azapi_resource" "rg" {
  type     = "Microsoft.Resources/resourceGroups@2021-04-01"
  name     = var.resource_group_name
  location = var.location
  tags     = var.tags
}

########################################################################
## Foundry resource
##
## `allowProjectManagement = true` is what makes this a Foundry resource
## rather than a plain Cognitive Services account.
##
## `customSubDomainName` is REQUIRED — without it the
## https://<name>.services.ai.azure.com endpoint does not exist, and every
## stateful Foundry feature (agents, Anthropic endpoint) fails.
########################################################################
resource "azapi_resource" "foundry" {
  type                      = "Microsoft.CognitiveServices/accounts@2025-06-01"
  name                      = local.foundry_name
  parent_id                 = azapi_resource.rg.id
  location                  = var.location
  schema_validation_enabled = false
  tags                      = var.tags

  identity {
    type = "SystemAssigned"
  }

  body = {
    kind = "AIServices"
    sku = {
      name = "S0"
    }
    properties = {
      # Entra ID is the intended auth path for this demo; local keys stay
      # available as a break-glass option but the notebook does not use them.
      disableLocalAuth       = false
      allowProjectManagement = true
      customSubDomainName    = local.foundry_name
      publicNetworkAccess    = "Enabled"
    }
  }

  response_export_values = ["properties.endpoint", "identity.principalId"]
}

########################################################################
## Foundry project
##
## Created with azapi rather than azurerm_cognitive_account_project: the
## azurerm path does not establish the AI Services connection, and projects
## created that way fail from Agent Framework clients with
## "404 ResourceNotFound — The project does not exist".
########################################################################
resource "azapi_resource" "project" {
  type                      = "Microsoft.CognitiveServices/accounts/projects@2025-06-01"
  name                      = "${var.project_name}-triage"
  parent_id                 = azapi_resource.foundry.id
  location                  = var.location
  schema_validation_enabled = false
  tags                      = var.tags

  identity {
    type = "SystemAssigned"
  }

  body = {
    properties = {
      displayName = "SOC Email Triage"
      description = "Blue-team email triage agent — Sublime + VirusTotal enrichment."
    }
  }

  response_export_values = ["properties.endpoints"]
}

########################################################################
## Model deployments
##
## Claude models require an Azure Marketplace subscription (Claude
## Consumption Units). If the offer has not been accepted on this
## subscription, these will fail — set deploy_claude_models = false,
## accept the offer in the portal, then re-apply.
########################################################################
resource "azapi_resource" "triage_model" {
  count = var.deploy_claude_models ? 1 : 0

  type      = "Microsoft.CognitiveServices/accounts/deployments@2025-06-01"
  name      = var.triage_model
  parent_id = azapi_resource.foundry.id

  schema_validation_enabled = false

  body = {
    sku = {
      name     = "GlobalStandard"
      capacity = var.triage_model_capacity
    }
    properties = {
      model = {
        format = "Anthropic"
        name   = var.triage_model
      }
    }
  }

  depends_on = [azapi_resource.project]
}

resource "azapi_resource" "escalation_model" {
  count = var.deploy_claude_models ? 1 : 0

  type      = "Microsoft.CognitiveServices/accounts/deployments@2025-06-01"
  name      = var.escalation_model
  parent_id = azapi_resource.foundry.id

  schema_validation_enabled = false

  body = {
    sku = {
      name     = "GlobalStandard"
      capacity = var.escalation_model_capacity
    }
    properties = {
      model = {
        format = "Anthropic"
        name   = var.escalation_model
      }
    }
  }

  # Deployments on the same account serialize server-side; chaining them
  # avoids a spurious conflict on parallel create.
  depends_on = [azapi_resource.triage_model]
}

########################################################################
## Observability
########################################################################
resource "azurerm_log_analytics_workspace" "logs" {
  count = var.enable_app_insights ? 1 : 0

  name                = "log-${local.foundry_name}"
  location            = var.location
  resource_group_name = var.resource_group_name
  sku                 = "PerGB2018"
  retention_in_days   = 30
  tags                = var.tags

  depends_on = [azapi_resource.rg]
}

resource "azurerm_application_insights" "insights" {
  count = var.enable_app_insights ? 1 : 0

  name                = "appi-${local.foundry_name}"
  location            = var.location
  resource_group_name = var.resource_group_name
  application_type    = "other"
  workspace_id        = azurerm_log_analytics_workspace.logs[0].id
  tags                = var.tags
}

########################################################################
## RBAC
##
## Analysts get "Foundry User" (formerly "Azure AI User" — the role ID is
## unchanged) so the notebook can authenticate as the human running it.
## That keeps the Foundry audit trail attributable to a person.
##
## Pinned by ID rather than looked up by name. The display name has already
## changed once, and a name lookup makes the provider enumerate every role
## definition in the subscription before filtering client-side, which is slow.
########################################################################
locals {
  foundry_user_role_definition_id = "/subscriptions/${var.subscription_id}/providers/Microsoft.Authorization/roleDefinitions/53ca6127-db72-4b80-b1b0-d745d6d5456d"
}

resource "azurerm_role_assignment" "analysts" {
  for_each = toset(var.analyst_principal_ids)

  scope              = azapi_resource.foundry.id
  role_definition_id = local.foundry_user_role_definition_id
  principal_id       = each.value
}
