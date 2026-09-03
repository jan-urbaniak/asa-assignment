variable "location" {
  type        = string
  description = "Azure region for the deployment."
  default     = "westeurope"
}

variable "name_prefix" {
  type        = string
  description = "Lowercase prefix used for Azure resource names."
  default     = "vulntracker"

  validation {
    condition     = can(regex("^[a-z0-9-]{1,20}$", var.name_prefix))
    error_message = "name_prefix must contain only lowercase letters, numbers, and dashes, and be at most 20 characters."
  }
}

variable "image" {
  type        = string
  description = "Immutable ACR image reference, preferably using a digest."
}

variable "key_vault_name" {
  type        = string
  description = "Existing Azure Key Vault containing application secrets."
}

variable "key_vault_resource_group_name" {
  type        = string
  description = "Resource group containing the existing Azure Key Vault."
}

variable "secret_key_name" {
  type        = string
  description = "Key Vault secret name containing the JWT signing key."
  default     = "secret-key"
}

variable "notify_service_key_name" {
  type        = string
  description = "Key Vault secret name containing the notify service key."
  default     = "notify-service-key"
}

variable "storage_encryption_key_name" {
  type        = string
  description = "Key Vault key name used for customer-managed storage encryption."
  default     = "vulntracker-storage-key"
}

variable "public_base_url" {
  type        = string
  description = "Trusted public base URL used to generate share links."
}

variable "api_port" {
  type        = number
  description = "TCP port on which the FastAPI container listens and is exposed."
  default     = 8000

  validation {
    condition     = var.api_port >= 1 && var.api_port <= 65535 && floor(var.api_port) == var.api_port
    error_message = "api_port must be an integer between 1 and 65535."
  }
}

variable "allowed_ingress_cidr" {
  type        = string
  description = "CIDR range allowed to reach the private ACI endpoint on api_port."

  validation {
    condition     = can(cidrhost(var.allowed_ingress_cidr, 0))
    error_message = "allowed_ingress_cidr must be a valid IPv4 or IPv6 CIDR."
  }
}

variable "vnet_address_space" {
  type        = list(string)
  description = "Address spaces assigned to the application VNet."

  validation {
    condition     = length(var.vnet_address_space) > 0 && alltrue([for cidr in var.vnet_address_space : can(cidrhost(cidr, 0))])
    error_message = "vnet_address_space must contain at least one valid CIDR."
  }
}

variable "aci_subnet_name" {
  type        = string
  description = "Name of the delegated subnet used by Azure Container Instances."
  default     = "aci"
}

variable "aci_subnet_address_prefixes" {
  type        = list(string)
  description = "Address prefixes assigned to the delegated ACI subnet."

  validation {
    condition     = length(var.aci_subnet_address_prefixes) > 0 && alltrue([for cidr in var.aci_subnet_address_prefixes : can(cidrhost(cidr, 0))])
    error_message = "aci_subnet_address_prefixes must contain at least one valid CIDR."
  }
}

variable "private_endpoint_subnet_name" {
  type        = string
  description = "Name of the subnet used by Azure Private Endpoints."
  default     = "private-endpoints"
}

variable "private_endpoint_subnet_address_prefixes" {
  type        = list(string)
  description = "Address prefixes assigned to the Private Endpoint subnet."
  default     = ["10.42.2.0/24"]

  validation {
    condition     = length(var.private_endpoint_subnet_address_prefixes) > 0 && alltrue([for cidr in var.private_endpoint_subnet_address_prefixes : can(cidrhost(cidr, 0))])
    error_message = "private_endpoint_subnet_address_prefixes must contain at least one valid CIDR."
  }
}

variable "container_cpu" {
  type        = number
  description = "Number of CPU cores allocated to the container."
  default     = 1
}

variable "container_memory_gb" {
  type        = number
  description = "Memory in GB allocated to the container."
  default     = 1.5
}

variable "notify_service_url" {
  type        = string
  description = "Internal URL of the notification service."
  default     = "http://vulntracker-notify:3001"
}

variable "tags" {
  type        = map(string)
  description = "Tags applied to Azure resources."
  default     = {}
}
