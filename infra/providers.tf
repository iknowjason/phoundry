terraform {
  required_version = ">= 1.9"

  required_providers {
    # AzAPI is the primary provider here. AzureRM cannot create Foundry
    # connections or capability hosts, and Foundry projects created with
    # azurerm are known to fail from Agent Framework clients with
    # "404 ResourceNotFound — The project does not exist" because the
    # AI Services connection is never established.
    azapi = {
      source  = "Azure/azapi"
      version = "~> 2.4"
    }
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }
}

provider "azapi" {
  subscription_id = var.subscription_id
}

provider "azurerm" {
  features {}
  subscription_id = var.subscription_id
}
