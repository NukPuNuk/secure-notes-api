# INTENTIONALLY INSECURE. For IaC scanning demonstration only. Never deploy.
#
# Models the Azure resources a Notes API might need: storage for note
# attachments, a network security group for the app VM, and a Key Vault for
# secrets. Each resource carries a common real-world misconfiguration.

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

resource "azurerm_resource_group" "notes" {
  name     = "rg-secure-notes-insecure"
  location = "eastus"
}

# Storage for note attachments (would hold ePHI).
resource "azurerm_storage_account" "notes" {
  name                            = "securenotesinsecure"
  resource_group_name             = azurerm_resource_group.notes.name
  location                        = azurerm_resource_group.notes.location
  account_tier                    = "Standard"
  account_replication_type        = "LRS"
  min_tls_version                 = "TLS1_0" # deprecated TLS allowed
  https_traffic_only_enabled      = false    # plain HTTP allowed
  allow_nested_items_to_be_public = true     # blobs can be made anonymously public
  public_network_access_enabled   = true     # reachable from the whole internet
}

# Network rules for the app VM.
resource "azurerm_network_security_group" "app" {
  name                = "nsg-app-insecure"
  location            = azurerm_resource_group.notes.location
  resource_group_name = azurerm_resource_group.notes.name

  security_rule {
    name                       = "allow-rdp-from-anywhere"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "3389" # RDP
    source_address_prefix      = "*"    # from any IP on the internet
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "allow-ssh-from-anywhere"
    priority                   = 110
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "22" # SSH
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
}

# Secrets store for the API.
resource "azurerm_key_vault" "kv" {
  name                          = "kv-notes-insecure"
  location                      = azurerm_resource_group.notes.location
  resource_group_name           = azurerm_resource_group.notes.name
  tenant_id                     = var.tenant_id
  sku_name                      = "standard"
  purge_protection_enabled      = false # deleted secrets can be permanently purged immediately
  public_network_access_enabled = true  # reachable from the internet, no network ACLs
}
