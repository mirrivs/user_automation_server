import configparser
import base64
import binascii
import logging
import os
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from auth import ClientIdentity
from client import broadcast_client_screenshot, broadcast_client_status, client_sockets, clients_info
from service_auth import require_service_token

config = configparser.ConfigParser()
config.read(os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.ini"))

MIN_INTERVAL_SECONDS = config.getint("DEFAULT", "screenshot_min_interval_seconds", fallback=10)
MAX_INTERVAL_SECONDS = config.getint("DEFAULT", "screenshot_max_interval_seconds", fallback=86400)
MAX_SCREENSHOT_SIZE_BYTES = config.getint("DEFAULT", "screenshot_max_size_mb", fallback=32) * 1024 * 1024
ALLOWED_CONTENT_TYPES = {"image/png", "image/jpeg"}

router = APIRouter()


class ScreenshotIntervalResponse(BaseModel):
    message: str
    status: str
    client_username: str
    interval_seconds: float
    clients_notified: int


@router.post(
    "/interval",
    response_model=ScreenshotIntervalResponse,
    description="Set the periodic screenshot-capture interval (in seconds) for a client. "
    "The client decides how to capture/send screenshots; the server only delegates the interval. "
    "Pushed immediately to any currently connected socket(s) for that user, and re-attached to the "
    "client config returned on every future `/client/connect`.",
    dependencies=[Depends(require_service_token)],
)
async def set_screenshot_interval(client_username: str, interval_seconds: float) -> ScreenshotIntervalResponse:
    if not (MIN_INTERVAL_SECONDS <= interval_seconds <= MAX_INTERVAL_SECONDS):
        raise HTTPException(
            status_code=422,
            detail=f"Interval must be between {MIN_INTERVAL_SECONDS} and {MAX_INTERVAL_SECONDS} seconds",
        )

    matched_hostnames = [hostname for hostname, info in clients_info.items() if info["username"] == client_username]
    if not matched_hostnames:
        return ScreenshotIntervalResponse(
            message=f"Client '{client_username}' is not currently known",
            status="error",
            client_username=client_username,
            interval_seconds=interval_seconds,
            clients_notified=0,
        )

    for hostname in matched_hostnames:
        clients_info[hostname]["screenshot_interval_seconds"] = interval_seconds
        clients_info[hostname]["client_config"]["screenshot"] = {"interval_seconds": interval_seconds}

    sockets = [socket for socket, username in client_sockets.connected_sockets.items() if username == client_username]
    for socket in sockets:
        await socket.send_json({"action": "set_screenshot_interval", "interval_seconds": interval_seconds})

    await broadcast_client_status()

    message = f"Screenshot interval set to {interval_seconds}s for client '{client_username}'"

    return ScreenshotIntervalResponse(
        message=message,
        status="success",
        client_username=client_username,
        interval_seconds=interval_seconds,
        clients_notified=len(sockets),
    )


async def receive_screenshot(data: dict, identity: ClientIdentity) -> None:
    """Validate and relay a screenshot without writing it to persistent storage."""
    content_type = data.get("content_type", "image/png")
    if content_type not in ALLOWED_CONTENT_TYPES:
        logging.warning("Ignoring unsupported screenshot content type %r from %s", content_type, identity.username)
        return

    encoded = data.get("image_base64")
    if not isinstance(encoded, str):
        logging.warning("Ignoring screenshot without base64 image data from %s", identity.username)
        return
    try:
        contents = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError):
        logging.warning("Ignoring invalid base64 screenshot from %s", identity.username)
        return

    if len(contents) > MAX_SCREENSHOT_SIZE_BYTES:
        logging.warning("Ignoring oversized screenshot from %s (%d bytes)", identity.username, len(contents))
        return

    now = datetime.now(timezone.utc)
    logging.info(f"Relaying screenshot from {identity.hostname} ({identity.username}), {len(contents)} bytes")

    if identity.hostname in clients_info:
        clients_info[identity.hostname]["connected"] = True
        clients_info[identity.hostname]["last_screenshot_at"] = now.isoformat()
        clients_info[identity.hostname]["last_seen_at"] = now.timestamp()
        await broadcast_client_screenshot(
            {
                "type": "screenshot",
                "hostname": identity.hostname,
                "timestamp": data.get("timestamp", now.timestamp()),
                "content_type": content_type,
                "image_base64": encoded,
            }
        )
        await broadcast_client_status()
