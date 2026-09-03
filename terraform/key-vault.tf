data "azurerm_key_vault" "app" {
  name                = var.key_vault_name
  resource_group_name = var.key_vault_resource_group_name
}

resource "azurerm_resource_group" "app" {
  name     = "${var.name_prefix}-aci-rg"
  location = var.location
  tags     = var.tags
}

resource "azurerm_user_assigned_identity" "aci" {
  name                = "${var.name_prefix}-aci-identity"
  resource_group_name = azurerm_resource_group.app.name
  location            = azurerm_resource_group.app.location
  tags                = var.tags
}

resource "azurerm_key_vault_key" "storage" {
  #checkov:skip=CKV_AZURE_40:Key expiry and rotation require an operational Key Vault lifecycle policy; the application has no automated key-rotation workflow yet.
  name         = var.storage_encryption_key_name
  key_vault_id = data.azurerm_key_vault.app.id
  key_type     = "RSA-HSM"
  key_size     = 2048
  key_opts     = ["decrypt", "encrypt", "unwrapKey", "wrapKey"]
}

resource "azurerm_user_assigned_identity" "storage" {
  name                = "${var.name_prefix}-storage-identity"
  resource_group_name = azurerm_resource_group.app.name
  location            = azurerm_resource_group.app.location
  tags                = var.tags
}

resource "azurerm_role_assignment" "storage_key_user" {
  scope                = data.azurerm_key_vault.app.id
  role_definition_name = "Key Vault Crypto Service Encryption User"
  principal_id         = azurerm_user_assigned_identity.storage.principal_id
}

resource "azurerm_role_assignment" "aci_key_vault_secrets_user" {
  scope                = data.azurerm_key_vault.app.id
  role_definition_name = "Key Vault Secrets User"
  principal_id         = azurerm_user_assigned_identity.aci.principal_id
}
