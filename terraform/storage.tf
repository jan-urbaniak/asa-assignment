resource "azurerm_storage_account" "data" {
  #checkov:skip=CKV_AZURE_33:The prototype does not use the Azure Queue service; queue logging is not applicable.
  #checkov:skip=CKV_AZURE_43:The storage account name is generated from a validated and truncated lowercase prefix; Checkov cannot evaluate this expression statically.
  #checkov:skip=CKV2_AZURE_40:ACI Azure Files mounting requires storage_account_key; disabling Shared Key would make the volume unusable with azurerm_container_group.
  #checkov:skip=CKV_AZURE_206:The prototype uses locally redundant storage (LRS) for a single-region SQLite workload; geo-replication is a future availability decision.
  name                            = substr("${replace(var.name_prefix, "-", "")}data", 0, 24)
  resource_group_name             = azurerm_resource_group.app.name
  location                        = azurerm_resource_group.app.location
  account_tier                    = "Standard"
  account_replication_type        = "LRS"
  min_tls_version                 = "TLS1_2"
  shared_access_key_enabled       = true
  public_network_access_enabled   = false
  allow_nested_items_to_be_public = false
  tags                            = var.tags

  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.storage.id]
  }

  customer_managed_key {
    key_vault_key_id          = azurerm_key_vault_key.storage.id
    user_assigned_identity_id = azurerm_user_assigned_identity.storage.id
  }

  depends_on = [azurerm_role_assignment.storage_key_user]

  blob_properties {
    delete_retention_policy {
      days = 7
    }
  }

  sas_policy {
    expiration_period = "01.00:00:00"
    expiration_action = "Log"
  }
}

resource "azurerm_storage_share" "data" {
  name               = "vulntracker-data"
  storage_account_id = azurerm_storage_account.data.id
  quota              = 1
}

resource "azurerm_private_dns_zone" "storage_file" {
  name                = "privatelink.file.core.windows.net"
  resource_group_name = azurerm_resource_group.app.name
  tags                = var.tags
}

resource "azurerm_private_dns_zone_virtual_network_link" "storage_file" {
  name                  = "${var.name_prefix}-storage-file-dns-link"
  resource_group_name   = azurerm_resource_group.app.name
  private_dns_zone_name = azurerm_private_dns_zone.storage_file.name
  virtual_network_id    = azurerm_virtual_network.app.id
  registration_enabled  = false
  tags                  = var.tags
}

resource "azurerm_private_endpoint" "storage_file" {
  name                = "${var.name_prefix}-storage-file-pe"
  location            = azurerm_resource_group.app.location
  resource_group_name = azurerm_resource_group.app.name
  subnet_id           = azurerm_subnet.private_endpoints.id
  tags                = var.tags

  private_service_connection {
    name                           = "${var.name_prefix}-storage-file-connection"
    private_connection_resource_id = azurerm_storage_account.data.id
    is_manual_connection           = false
    subresource_names              = ["file"]
  }

  private_dns_zone_group {
    name                 = "default"
    private_dns_zone_ids = [azurerm_private_dns_zone.storage_file.id]
  }
}
