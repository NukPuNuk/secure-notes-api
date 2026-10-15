# Hardened counterpart of terraform/insecure/main.tf. Scanned, not deployed.
#
# Any Checkov check that is intentionally not satisfied is suppressed inline
# with a #checkov:skip comment and a written justification. Suppression is a
# documented risk decision, not a way to make the scanner quiet.

terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.0"
    }
  }
}

provider "azurerm" {
  features {}
}

variable "tenant_id" {
  type        = string
  description = "Entra ID tenant that owns the Key Vault"
}

variable "admin_cidr" {
  type        = string
  description = "The only network allowed to reach management ports (e.g. a Bastion subnet)"
  default     = "10.0.10.0/24"
}

resource "azurerm_resource_group" "notes" {
  name     = "rg-secure-notes"
  location = "eastus"
}

# Storage for note attachments (would hold ePHI).
resource "azurerm_storage_account" "notes" {
  #checkov:skip=CKV2_AZURE_1:Platform-managed keys (AES-256) meet current policy; customer-managed keys add a key-rotation burden and are revisited if a customer contract requires them
  #checkov:skip=CKV2_AZURE_33:Private endpoint is provisioned by the separate network module (out of scope for this demo); public network access is already disabled here
  #checkov:skip=CKV_AZURE_33:Queue service is not used by this application, so queue logging has no effect; blob access is the audited path
  name                            = "securenotessecure"
  resource_group_name             = azurerm_resource_group.notes.name
  location                        = azurerm_resource_group.notes.location
  account_tier                    = "Standard"
  account_replication_type        = "GRS"    # survives a regional outage
  min_tls_version                 = "TLS1_2" # modern TLS only
  https_traffic_only_enabled      = true     # no plain HTTP
  allow_nested_items_to_be_public = false    # no anonymous public blobs
  public_network_access_enabled   = false    # private access only
  shared_access_key_enabled       = false    # Entra ID auth only, no account keys to leak

  blob_properties {
    delete_retention_policy {
      days = 30 # recover accidentally deleted or ransomwared blobs
    }
  }

  network_rules {
    default_action = "Deny"
    bypass         = ["AzureServices"]
  }
}

# Network rules for the app VM: no management ports open to the internet.
# The internet-facing RDP/SSH rules from the insecure version are removed.
# Admins reach the VM only from the admin network (e.g. through Azure Bastion).
resource "azurerm_network_security_group" "app" {
  name                = "nsg-app"
  location            = azurerm_resource_group.notes.location
  resource_group_name = azurerm_resource_group.notes.name

  security_rule {
    name                       = "allow-ssh-from-admin-network"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "22"
    source_address_prefix      = var.admin_cidr # admin network only
    destination_address_prefix = "*"
  }
}

# Secrets store for the API.
resource "azurerm_key_vault" "kv" {
  #checkov:skip=CKV2_AZURE_32:Private endpoint is provisioned by the separate network module (out of scope for this demo); public network access is already disabled here
  name                          = "kv-secure-notes"
  location                      = azurerm_resource_group.notes.location
  resource_group_name           = azurerm_resource_group.notes.name
  tenant_id                     = var.tenant_id
  sku_name                      = "premium"
  purge_protection_enabled      = true  # deleted secrets can't be destroyed before retention ends
  soft_delete_retention_days    = 90
  public_network_access_enabled = false # private access only

  network_acls {
    default_action = "Deny"
    bypass         = "AzureServices"
  }
}
