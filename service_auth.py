import configparser
import os

from fastapi import Depends, HTTPException
from fastapi.security import APIKeyHeader

config = configparser.ConfigParser()
config.read("config.ini")

# Shared secret for service-to-service auth (the wizard backend -> this server).
# Prefer the env var; fall back to config.ini for local/dev.
SERVICE_API_KEY = os.getenv("SERVICE_API_KEY", config["DEFAULT"].get("service_api_key", ""))

SERVICE_API_KEY_HEADER = "X-API-Key"

_api_key_header = APIKeyHeader(name=SERVICE_API_KEY_HEADER, auto_error=False)


def is_valid_service_token(key: str | None) -> bool:
    """Return True if `key` matches the configured shared service token."""
    return bool(SERVICE_API_KEY) and key == SERVICE_API_KEY


def require_service_token(key: str = Depends(_api_key_header)) -> None:
    """FastAPI dependency guarding service-to-service endpoints with the shared key."""
    if not is_valid_service_token(key):
        raise HTTPException(status_code=401, detail="errors.invalid_auth_token")
