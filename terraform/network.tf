resource "azurerm_virtual_network" "app" {
  name                = "${var.name_prefix}-vnet"
  location            = azurerm_resource_group.app.location
  resource_group_name = azurerm_resource_group.app.name
  address_space       = var.vnet_address_space
  tags                = var.tags
}

resource "azurerm_network_security_group" "app" {
  name                = "${var.name_prefix}-aci-nsg"
  location            = azurerm_resource_group.app.location
  resource_group_name = azurerm_resource_group.app.name
  tags                = var.tags

  security_rule {
    name                       = "allow-api-from-approved-network"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = tostring(var.api_port)
    source_address_prefix      = var.allowed_ingress_cidr
    destination_address_prefix = "*"
  }
}

resource "azurerm_subnet" "aci" {
  name                 = var.aci_subnet_name
  resource_group_name  = azurerm_resource_group.app.name
  virtual_network_name = azurerm_virtual_network.app.name
  address_prefixes     = var.aci_subnet_address_prefixes
  service_endpoints    = ["Microsoft.KeyVault", "Microsoft.Storage"]

  delegation {
    name = "aci-delegation"

    service_delegation {
      name = "Microsoft.ContainerInstance/containerGroups"
      actions = [
        "Microsoft.Network/virtualNetworks/subnets/action",
      ]
    }
  }
}

resource "azurerm_subnet_network_security_group_association" "aci" {
  subnet_id                 = azurerm_subnet.aci.id
  network_security_group_id = azurerm_network_security_group.app.id
}

resource "azurerm_subnet" "private_endpoints" {
  name                              = var.private_endpoint_subnet_name
  resource_group_name               = azurerm_resource_group.app.name
  virtual_network_name              = azurerm_virtual_network.app.name
  address_prefixes                  = var.private_endpoint_subnet_address_prefixes
  private_endpoint_network_policies = "Disabled"
}

resource "azurerm_subnet_network_security_group_association" "private_endpoints" {
  subnet_id                 = azurerm_subnet.private_endpoints.id
  network_security_group_id = azurerm_network_security_group.app.id
}
