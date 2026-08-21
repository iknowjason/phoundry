output "foundry_resource_name" {
  description = "Set this as ANTHROPIC_FOUNDRY_RESOURCE in .env"
  value       = azapi_resource.foundry.name
}

output "foundry_endpoint" {
  description = "Base Foundry endpoint."
  value       = try(azapi_resource.foundry.output.properties.endpoint, null)
}

output "anthropic_endpoint" {
  description = "Anthropic Messages endpoint used for Claude models."
  value       = "https://${azapi_resource.foundry.name}.services.ai.azure.com/anthropic/v1/messages"
}

output "project_name" {
  description = "Foundry project name."
  value       = azapi_resource.project.name
}

output "project_endpoint" {
  description = "Set this as FOUNDRY_PROJECT_ENDPOINT in .env"
  value       = try(azapi_resource.project.output.properties.endpoints["AI Foundry API"], "https://${azapi_resource.foundry.name}.services.ai.azure.com")
}

output "triage_model" {
  description = "Set this as TRIAGE_MODEL in .env"
  value       = var.deploy_claude_models ? var.triage_model : "(not deployed)"
}

output "escalation_model" {
  description = "Set this as ESCALATION_MODEL in .env"
  value       = var.deploy_claude_models ? var.escalation_model : "(not deployed)"
}

output "app_insights_connection_string" {
  description = "Application Insights connection string for agent tracing."
  value       = var.enable_app_insights ? azurerm_application_insights.insights[0].connection_string : null
  sensitive   = true
}

output "env_file_snippet" {
  description = "Paste this into .env"
  value       = <<-ENVFILE
    ANTHROPIC_FOUNDRY_RESOURCE=${azapi_resource.foundry.name}
    FOUNDRY_PROJECT_ENDPOINT=https://${azapi_resource.foundry.name}.services.ai.azure.com
    TRIAGE_MODEL=${var.triage_model}
    ESCALATION_MODEL=${var.escalation_model}
  ENVFILE
}
