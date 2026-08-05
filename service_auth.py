import configparser
import os

from fastapi import Depends, HTTPException
from fastapi.security import APIKeyHeader

config = configparser.ConfigParser()
config.read(os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.ini"))


def _clean_secret(value: str | None) -> str:
    """Strip any inline `;`/`#` comment and surrounding whitespace from a config value.

    configparser does not treat an inline `;`/`#` as a comment unless it is preceded
    by whitespace, so a value like `KEY;note` would otherwise include the note. The
    shared token is a URL-safe string (no `;`/`#`), so this is safe.
    """
    if not value:
        return ""
    return value.split(";", 1)[0].split("#", 1)[0].strip()


# Shared secret for service-to-service auth (the wizard backend -> this server).
# Prefer the env var; fall back to config.ini for local/dev.
SERVICE_API_KEY = _clean_secret(os.getenv("SERVICE_API_KEY") or config["DEFAULT"].get("service_api_key", ""))

SERVICE_API_KEY_HEADER = "X-API-Key"

_api_key_header = APIKeyHeader(name=SERVICE_API_KEY_HEADER, auto_error=False)


def is_valid_service_token(key: str | None) -> bool:
    """Return True if `key` matches the configured shared service token."""
    expected = SERVICE_API_KEY
    if not os.getenv("SERVICE_API_KEY"):
        # Local development commonly edits config.ini while uvicorn's reloader
        # is running; config files don't trigger a Python module reload.
        live_config = configparser.ConfigParser()
        live_config.read(os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.ini"))
        expected = _clean_secret(live_config["DEFAULT"].get("service_api_key", ""))
    return bool(expected) and key == expected


def require_service_token(key: str = Depends(_api_key_header)) -> None:
    """FastAPI dependency guarding service-to-service endpoints with the shared key."""
    if not is_valid_service_token(key):
        raise HTTPException(status_code=401, detail="errors.invalid_auth_token")
