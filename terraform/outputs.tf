output "resource_group_name" {
  value = azurerm_resource_group.app.name
}

output "container_group_name" {
  value = azurerm_container_group.api.name
}

output "private_ip_address" {
  value = azurerm_container_group.api.ip_address
}

output "aci_identity_client_id" {
  value = azurerm_user_assigned_identity.aci.client_id
}
