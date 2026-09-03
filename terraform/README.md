# VulnTracker on Azure Container Instances

This Terraform configuration deploys the FastAPI image to Azure Container
Instances (ACI). It is intentionally small and suitable for a single-instance
prototype.

## Secret handling

ACI does not provide a native Key Vault reference in container environment
variables. The container uses its User Assigned Managed Identity and the Azure
Key Vault SDK to retrieve secrets at startup.

Therefore:

- secret values are not stored in this repository, ACI definition, or Terraform state;
- the ACI managed identity receives only the `Key Vault Secrets User` role on the
  selected vault;
- the deployment identity running Terraform needs read access to discover the
  vault and create the role assignment;
- never commit `terraform.tfstate`, plan files, or `.tfvars` containing secrets.

The application reads `AZURE_KEY_VAULT_URL`, `AZURE_SECRET_KEY_NAME`, and
`AZURE_NOTIFY_SERVICE_KEY_NAME` as non-secret configuration. Local development
may still provide `SECRET_KEY` and `NOTIFY_SERVICE_KEY` directly; direct local
values take precedence and do not require an Azure login.

## Usage

Authenticate with Azure and select a subscription, then provide an existing
Key Vault and an immutable image reference:

```bash
terraform init
terraform fmt -check
tflint --init
tflint --format compact
terraform validate
terraform plan \
  -var='key_vault_name=<key-vault-name>' \
  -var='key_vault_resource_group_name=<key-vault-resource-group>' \
  -var='image=<acr-name>.azurecr.io/vulntracker-api@sha256:<digest>' \
  -var='public_base_url=http://10.42.1.10:8000' \
  -var='allowed_ingress_cidr=10.42.0.0/16' \
  -var='vnet_address_space=["10.42.0.0/16"]' \
  -var='aci_subnet_name=aci' \
  -var='aci_subnet_address_prefixes=["10.42.1.0/24"]'
terraform apply
```

The VNet and subnet CIDRs are variables so they can be replaced with ranges
from the target Azure network. `allowed_ingress_cidr` should be narrower than
the VNet space in production and must be able to route to the private ACI
subnet.

`api_port` must match the `APP_PORT` build argument used when creating the
container image. The default for both is `8000`.

The deployment identity running Terraform needs permission to read the Key
Vault metadata and create the role assignment. The ACI managed identity is
used by the application at runtime to retrieve the two secrets.

The storage account uses an HSM-backed customer-managed key from Key Vault.
The Key Vault must use the Premium SKU for `RSA-HSM` keys.

The following Checkov controls are suppressed as inline comments in
`terraform/main.tf`, directly on the affected resources:

- `CKV_AZURE_40`: Key expiry and rotation need an operational Key Vault
  lifecycle process that is not implemented in this prototype.
- `CKV_AZURE_98` and `CKV_AZURE_245`: retained for compatibility with older
  Checkov versions; the current deployment uses a private ACI subnet and NSG.
- `CKV_AZURE_235`: ACI has no native Key Vault reference for environment
  variables, and the application requires non-secret runtime configuration as
  ordinary environment variables. The two secrets are fetched at runtime from
  Key Vault by Managed Identity.
- `CKV_AZURE_33`: the prototype does not use the Azure Queue service, so queue
  logging is not applicable.
- `CKV_AZURE_43`: the storage-account name is generated from a validated and
  truncated lowercase prefix; Checkov cannot evaluate the expression
  statically.
- `CKV_AZURE_59`: retained for compatibility with older Checkov versions; the
  current Storage Account has public network access disabled and uses an Azure
  Files Private Endpoint.
- `CKV2_AZURE_40`: ACI Azure Files mounting requires `storage_account_key` in
  the current provider, so Shared Key cannot yet be disabled without breaking
  the volume mount. This is the remaining storage exception.
- `CKV_AZURE_206`: the prototype uses locally redundant storage (LRS) for a
  single-region SQLite workload; geo-replication is a future availability
  decision.

These are explicit risk acceptances, not a global scanner bypass. In
production, remove the Azure Files Shared Key dependency by moving to a runtime
that supports managed-identity storage access, and implement managed key
rotation.

For a production deployment, place the Terraform state in an encrypted Azure
Storage backend with private network access and strict RBAC. ACI uses a private
IP and NSG allowlist in this configuration; the allowed CIDR must be limited to
the ingress network that actually needs the API.

The output `private_ip_address` identifies the private ACI endpoint. ACI exposes
only `api_port` to the configured CIDR, and passes the same value to the image's
`PORT` setting. The container runs as UID 10001, has CPU and memory limits, and
has a health probe for `/health`.
