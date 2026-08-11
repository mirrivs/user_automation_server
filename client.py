import configparser
import json
import logging
import os
import time
from typing import Annotated

import yaml
from fastapi import APIRouter, Depends, Form, HTTPException
from fastapi.security import OAuth2PasswordRequestForm
from jose import jwt
from pydantic import BaseModel

from auth import ClientIdentity, current_client, current_user
from config_generator import ConfigGenerator
from hostname import is_valid_hostname
from models.client_config import ClientConfig
from parse_credentials import parse_user_credentials
from service_auth import is_valid_service_token, require_service_token
from sockets import SocketManager

# Load configuration from environment variables or a file
JWT_SECRET = os.getenv("JWT_SECRET", "ExgEFKuRnzSZhjAq")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
JWT_EXPIRATION = int(os.getenv("JWT_EXPIRATION", 36000))  # seconds

config = configparser.ConfigParser()
config.read(os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.ini"))

# Default delivered through the existing generic client-config merge path.
DEFAULT_SCREENSHOT_INTERVAL_SECONDS = config.getfloat("DEFAULT", "screenshot_default_interval_seconds", fallback=10)
CLIENT_OFFLINE_TIMEOUT_SECONDS = config.getfloat("DEFAULT", "client_offline_timeout_seconds", fallback=90)
if CLIENT_OFFLINE_TIMEOUT_SECONDS <= 0:
    raise ValueError("client_offline_timeout_seconds must be positive")

# Clients released before capability reporting was added do not include either
# ``available_behaviours`` or ``behaviour_toggles`` in their /connect request.
# These are the behaviour IDs implemented by those clients and supported by
# this server. Keep the list here (rather than all server enum values) so a
# legacy client is never offered a server-only behaviour such as
# ``attack_phishing_attachment``.
LEGACY_CLIENT_BEHAVIOURS = frozenset(
    {
        "attack_phishing",
        "attack_ransomware",
        "attack_reverse_shell",
        "procrastination",
        "work_emails",
        "work_organization_web",
    }
)


class ClientInfo(BaseModel):
    username: str
    hostname: str
    # A disconnected client remains in the status list so operators can see it
    # and distinguish it from a machine that has never registered.
    connected: bool = True
    current_behaviour: str | None
    client_config: ClientConfig
    work_cycle_active: bool | None = None
    # Behaviours the client reported it can run on /connect. Legacy clients that
    # do not report a set are populated with LEGACY_CLIENT_BEHAVIOURS.
    available_behaviours: list[str] | None = None
    # Positive capture cadence in seconds delivered to this client.
    screenshot_interval_seconds: float | None = None
    # ISO timestamp of the last screenshot the server received from this client.
    last_screenshot_at: str | None = None
    # Unix timestamp of the last authenticated client activity.
    last_seen_at: float | None = None


def parse_available_behaviours(raw: str | None) -> list[str] | None:
    """Parse the client-reported available behaviours from the connect form.

    The client reports the behaviours it can run as either a JSON array
    (e.g. '["procrastination", "work_emails"]') or a comma-separated string.
    Returns None when the client reports nothing; callers map that to the
    pre-capability-reporting client compatibility set.
    """
    if raw is None or raw.strip() == "":
        return None

    try:
        parsed = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        parsed = [item.strip() for item in raw.split(",")]

    if not isinstance(parsed, list):
        return None

    return [str(item).strip() for item in parsed if str(item).strip()]


def parse_behaviour_toggles(raw: str | None) -> list[str] | None:
    """Derive enabled behaviour IDs from a client's rendered config toggle map."""
    if raw is None or raw.strip() == "":
        return None

    try:
        parsed = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        try:
            parsed = yaml.safe_load(raw)
        except yaml.YAMLError:
            return None

    if not isinstance(parsed, dict):
        return None

    # Accept either the toggle map itself or the complete rendered config.yml.
    toggles = parsed.get("automation", {}).get("behaviour_toggles") if "automation" in parsed else parsed
    if not isinstance(toggles, dict):
        return None
    return sorted(str(behaviour) for behaviour, enabled in toggles.items() if enabled is True)


def reported_or_legacy_behaviours(reported: list[str] | None) -> list[str]:
    """Return explicit capabilities, or the known set for pre-reporting clients.

    An empty explicit list is meaningful: it means the client deliberately
    disabled every behaviour and must not be replaced by the legacy fallback.
    """
    if reported is not None:
        return reported
    return sorted(LEGACY_CLIENT_BEHAVIOURS)


class OAuth2PasswordRequestFormWithHostname(OAuth2PasswordRequestForm):
    def __init__(
        self,
        *,
        username: Annotated[str, Form()],
        password: Annotated[str, Form()],
        hostname: Annotated[str, Form()],
        available_behaviours: Annotated[str | None, Form()] = None,
        behaviour_toggles: Annotated[str | None, Form()] = None,
    ):
        super().__init__(
            username=username,
            password=password,
            scope="",
            client_id=None,
            client_secret=None,
        )
        self.hostname = hostname
        # The rendered toggle map is authoritative. Keep the old explicit list
        # as a migration fallback for already-deployed clients.
        self.available_behaviours = parse_behaviour_toggles(behaviour_toggles)
        if self.available_behaviours is None:
            self.available_behaviours = parse_available_behaviours(available_behaviours)


cwd = os.path.abspath(os.path.dirname(__file__))
config_file = os.path.join(cwd, "config.yml")
user_credentials_file = os.path.join(cwd, "user_credentials.yml")
config_generation_file = os.path.join(cwd, "config_generator.yml")

user_credentials = parse_user_credentials(user_credentials_file)


if config.getboolean("DEFAULT", "use_hybrid_mail_domain"):
    credentials = user_credentials.get("external_user_credentials", [])
else:
    credentials = user_credentials.get("internal_user_credentials", [])

available_client_users = {user["username"]: user for user in credentials}

clients_info: dict[str, ClientInfo] = {}

config_generator = None

with open(config_generation_file, "r") as stream:
    config_generator = ConfigGenerator(yaml.safe_load(stream).get("config_generation", {}))

router = APIRouter()


async def status_socket_auth(token: str) -> str:
    """
    Authenticate a status-socket subscriber. Accepts either the shared service API
    key (used by the wizard backend) or a valid dashboard JWT.
    """
    if is_valid_service_token(token):
        return "service"
    return await current_user(token)


async def send_client_status(websocket, identity=None):
    """Send the current client list to a freshly connected status subscriber."""
    await websocket.send_json({"clients_info": serialised_clients_info()})


async def update_client_status(data, websocket):
    """Update client status"""
    # Status subscribers are read-only; inbound messages are ignored.
    pass


async def send_client_config(websocket, username):
    """Send client config to websocket"""

    pass


async def update_client_config(data, websocket, identity: ClientIdentity):
    """Apply a live status update pushed by a connected client.

    Clients push frequent `status_update` messages over this socket to report
    their current behaviour and work-cycle state. These were previously only
    logged and discarded, so `clients_info` never reflected client-driven state
    changes and the dashboard never saw them (it had to fall back to polling
    the REST client list instead of getting pushed updates).
    """
    if not isinstance(data, dict):
        return

    if data.get("type") == "screenshot":
        # Local import avoids a module cycle: screenshot's admin/read routes use
        # the client registry maintained in this module.
        from screenshot import receive_screenshot

        await receive_screenshot(data, identity)
        return

    if data.get("type") != "status_update":
        return

    # Socket authentication is authoritative. The payload hostname is merely
    # informational and must never select another client's record.
    hostname = identity.hostname
    username = identity.username
    client = clients_info.get(hostname)
    if client is None or client["username"] != username:
        logging.warning(f"Status update for unknown client hostname '{hostname}' from user {username}")
        return

    client["connected"] = True
    client["last_seen_at"] = time.time()

    behaviour = data.get("current_behaviour")
    new_current_behaviour = behaviour.get("id") if isinstance(behaviour, dict) else behaviour
    new_work_cycle_active = (
        data["idle_cycle_status"] == "running" if "idle_cycle_status" in data else client["work_cycle_active"]
    )

    if client["current_behaviour"] == new_current_behaviour and client["work_cycle_active"] == new_work_cycle_active:
        return

    client["current_behaviour"] = new_current_behaviour
    client["work_cycle_active"] = new_work_cycle_active
    await broadcast_client_status()


client_status_sockets = SocketManager(
    router,
    "/client_status_socket",
    True,
    send_client_status,
    update_client_status,
    auth_func=status_socket_auth,
)
client_sockets = SocketManager(
    router,
    "/client_socket",
    True,
    send_client_config,
    update_client_config,
    auth_func=current_client,
)


async def broadcast_client_status():
    """Push the current client list to every connected status subscriber."""
    payload = {"clients_info": serialised_clients_info()}
    for websocket in list(client_status_sockets.connected_sockets.keys()):
        try:
            await websocket.send_json(payload)
        except Exception as ex:  # noqa: BLE001 - a dead subscriber must not abort the broadcast
            logging.warning(f"Dropping status subscriber, send failed: {ex}")
            client_status_sockets.connected_sockets.pop(websocket, None)


async def broadcast_client_screenshot(payload: dict):
    """Relay one screenshot to connected dashboards without persisting it."""
    for websocket in list(client_status_sockets.connected_sockets.keys()):
        try:
            await websocket.send_json(payload)
        except Exception as ex:  # noqa: BLE001 - a dead subscriber must not abort delivery
            logging.warning(f"Dropping status subscriber, screenshot send failed: {ex}")
            client_status_sockets.connected_sockets.pop(websocket, None)


class ClientsInfoResponse(BaseModel):
    clients_info: list[ClientInfo]


def serialised_clients_info() -> list[dict]:
    """Return client records with legacy capability reports normalised.

    This also fixes records that were connected before the server was upgraded:
    they remain in memory with ``available_behaviours=None`` until their next
    reconnect, but the dashboard can use the compatibility set immediately.
    """
    expire_inactive_clients()
    return [
        {
            **client,
            "available_behaviours": reported_or_legacy_behaviours(client.get("available_behaviours")),
        }
        for client in clients_info.values()
    ]


def expire_inactive_clients(now: float | None = None) -> bool:
    """Mark inactive clients offline while retaining their dashboard record."""
    now = time.time() if now is None else now
    changed = False
    for client in clients_info.values():
        last_seen_at = client.get("last_seen_at")
        if client.get("connected") and (
            last_seen_at is None or now - last_seen_at >= CLIENT_OFFLINE_TIMEOUT_SECONDS
        ):
            client["connected"] = False
            client["current_behaviour"] = None
            client["work_cycle_active"] = None
            changed = True
    return changed


@router.get(
    "/",
    response_model=ClientsInfoResponse,
    description="Get list of active clients, future status updates will be streamed via a websocket created like this:"
    "<br>`var socket = new WebSocket('ws://localhost:8000/client_status_socket');`",
    dependencies=[Depends(require_service_token)],
)
async def get_client_info() -> ClientInfo:
    return {"clients_info": serialised_clients_info()}


class ConnectResponse(BaseModel):
    access_token: str
    token_type: str
    client_config: ClientConfig


@router.post(
    "/connect",
    response_model=ConnectResponse,
    description="Add client to the list of active clients, future status updates will be "
    "streamed via a websocket created like this:<br>"
    '`var socket = new WebSocket("ws://localhost:8000/client_socket");`'
    "<br><br>**Required fields:** username, password, hostname",
)
async def connect_client(
    form_data: Annotated[OAuth2PasswordRequestFormWithHostname, Depends()],
) -> ConnectResponse:
    """
    Authenticate a user and generate a JWT token
    """
    if not form_data.hostname or len(form_data.hostname.strip()) == 0:
        logging.warning(f"Missing hostname for user {form_data.username}")
        raise HTTPException(status_code=400, detail="errors.hostname_required")

    if not is_valid_hostname(form_data.hostname):
        logging.warning(f"Invalid hostname '{form_data.hostname}' for user {form_data.username}")
        raise HTTPException(status_code=400, detail="errors.invalid_hostname")

    if not (
        form_data.username in available_client_users.keys()
        and form_data.password == available_client_users[form_data.username]["password"]
    ):
        logging.warning(f"Invalid login attempt from user {form_data.username} with hostname {form_data.hostname}")
        raise HTTPException(status_code=401, detail="errors.invalid_username_or_password")

    logging.info(f"User {form_data.username} logged in from hostname {form_data.hostname}")

    user = available_client_users[form_data.username]

    if form_data.hostname not in clients_info:
        clients_info[form_data.hostname] = {
            "username": form_data.username,
            "connected": True,
            "current_behaviour": None,
            "client_config": config_generator.generate_config(user["username"]),
            "hostname": form_data.hostname,
            "work_cycle_active": None,
            "available_behaviours": reported_or_legacy_behaviours(form_data.available_behaviours),
            "screenshot_interval_seconds": DEFAULT_SCREENSHOT_INTERVAL_SECONDS,
            "last_screenshot_at": None,
            "last_seen_at": time.time(),
        }
    else:
        clients_info[form_data.hostname]["hostname"] = form_data.hostname
        clients_info[form_data.hostname]["connected"] = True
        clients_info[form_data.hostname]["last_seen_at"] = time.time()
        clients_info[form_data.hostname]["current_behaviour"] = None
        clients_info[form_data.hostname]["work_cycle_active"] = None
        clients_info[form_data.hostname]["available_behaviours"] = reported_or_legacy_behaviours(
            form_data.available_behaviours
        )

    # Heal stale in-memory state left by an older server version that used 0 as
    # its default. The current client protocol only accepts positive numbers.
    if not clients_info[form_data.hostname].get("screenshot_interval_seconds", 0) > 0:
        clients_info[form_data.hostname]["screenshot_interval_seconds"] = DEFAULT_SCREENSHOT_INTERVAL_SECONDS

    # The screenshot interval is mutable server-side state (set via the wizard), so it is
    # re-attached to the generated config on every connect/reconnect rather than only once,
    # ensuring a restarted client picks up the current setting even without a live socket.
    clients_info[form_data.hostname]["client_config"]["screenshot"] = {
        "interval_seconds": clients_info[form_data.hostname]["screenshot_interval_seconds"]
    }

    await broadcast_client_status()

    token = jwt.encode(
        {
            "sub": user["username"],
            "hostname": form_data.hostname,
            "exp": int(time.time()) + JWT_EXPIRATION,
        },
        JWT_SECRET,
        algorithm=JWT_ALGORITHM,
    )

    return {
        "access_token": token,
        "token_type": "bearer",
        "client_config": clients_info[form_data.hostname]["client_config"],
    }


def get_reported_behaviours(username: str) -> set[str]:
    """Return the set of behaviours a user's connected client(s) reported as available.

    When the same user is connected from several hostnames the result is the
    intersection of every reported set, so the server only permits a behaviour
    that every target client can run. Pre-reporting clients use the explicit
    legacy compatibility set assigned at connect time.
    """
    reported_sets = [
        set(reported_or_legacy_behaviours(info.get("available_behaviours")))
        for info in clients_info.values()
        if info.get("username") == username and info.get("connected", True)
    ]
    if not reported_sets:
        return set()
    return set.intersection(*reported_sets)


@router.delete("/disconnect")
async def disconnect_client(hostname: str) -> dict:
    if hostname in clients_info:
        clients_info[hostname]["connected"] = False
        clients_info[hostname]["current_behaviour"] = None
        clients_info[hostname]["work_cycle_active"] = None
        await broadcast_client_status()
        return {"message": f"Client {hostname} disconnected"}
    else:
        raise HTTPException(status_code=404, detail="Client not found")
