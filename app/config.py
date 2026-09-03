import os

from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient


def _get_secret(environment_name: str, secret_name_env_var: str) -> str:
    value = os.environ.get(environment_name)
    if value:
        return value

    vault_url = os.environ.get("AZURE_KEY_VAULT_URL")
    secret_name = os.environ.get(secret_name_env_var)
    if not vault_url or not secret_name:
        raise RuntimeError(
            f"{environment_name} must be set, or both AZURE_KEY_VAULT_URL and {secret_name_env_var} must be configured"
        )

    client = SecretClient(vault_url=vault_url, credential=DefaultAzureCredential())
    return client.get_secret(secret_name).value


DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///./vulntracker.db")

SECRET_KEY = _get_secret("SECRET_KEY", "AZURE_SECRET_KEY_NAME")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

NOTIFY_SERVICE_URL = os.environ.get("NOTIFY_SERVICE_URL", "http://localhost:3001")
NOTIFY_SERVICE_KEY = _get_secret("NOTIFY_SERVICE_KEY", "AZURE_NOTIFY_SERVICE_KEY_NAME")

# This value must come from trusted deployment configuration, never from a request.
PUBLIC_BASE_URL = os.environ.get("PUBLIC_BASE_URL", "http://localhost:8000").rstrip("/")
