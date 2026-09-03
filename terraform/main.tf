resource "azurerm_container_group" "api" {
  #checkov:skip=CKV_AZURE_235:Non-secret runtime configuration is intentionally provided as plain environment variables; secrets are fetched at runtime from Key Vault via Managed Identity.
  name                = "${var.name_prefix}-api"
  location            = azurerm_resource_group.app.location
  resource_group_name = azurerm_resource_group.app.name
  ip_address_type     = "Private"
  subnet_ids          = [azurerm_subnet.aci.id]
  os_type             = "Linux"
  restart_policy      = "Always"
  tags                = var.tags

  exposed_port {
    port     = var.api_port
    protocol = "TCP"
  }

  container {
    name   = "api"
    image  = var.image
    cpu    = var.container_cpu
    memory = var.container_memory_gb

    ports {
      port     = var.api_port
      protocol = "TCP"
    }

    environment_variables = {
      PUBLIC_BASE_URL               = var.public_base_url
      NOTIFY_SERVICE_URL            = var.notify_service_url
      DATABASE_URL                  = "sqlite:////data/vulntracker.db"
      PORT                          = tostring(var.api_port)
      AZURE_KEY_VAULT_URL           = data.azurerm_key_vault.app.vault_uri
      AZURE_SECRET_KEY_NAME         = var.secret_key_name
      AZURE_NOTIFY_SERVICE_KEY_NAME = var.notify_service_key_name
    }

    volume {
      name                 = "data"
      mount_path           = "/data"
      storage_account_name = azurerm_storage_account.data.name
      storage_account_key  = azurerm_storage_account.data.primary_access_key
      share_name           = azurerm_storage_share.data.name
    }

    liveness_probe {
      http_get {
        path   = "/health"
        port   = var.api_port
        scheme = "Http"
      }
      initial_delay_seconds = 15
      period_seconds        = 20
      timeout_seconds       = 5
      failure_threshold     = 3
    }
  }

  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.aci.id]
  }

  depends_on = [
    azurerm_role_assignment.aci_key_vault_secrets_user,
    azurerm_subnet_network_security_group_association.aci,
  ]
}
