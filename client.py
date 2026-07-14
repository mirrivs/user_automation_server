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

from auth import current_user
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
config.read("config.ini")


class ClientInfo(BaseModel):
    username: str
    hostname: str
    current_behaviour: str | None
    client_config: ClientConfig
    idle_cycle_active: bool | None = None
    # Behaviours the client reported it can run on /connect. None means the client
    # did not report a set, so the server does not enforce availability for it.
    available_behaviours: list[str] | None = None


def parse_available_behaviours(raw: str | None) -> list[str] | None:
    """Parse the client-reported available behaviours from the connect form.

    The client reports the behaviours it can run as either a JSON array
    (e.g. '["procrastination", "work_emails"]') or a comma-separated string.
    Returns None when the client reports nothing, meaning "unknown" (the server
    then does not enforce availability for that client).
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


class OAuth2PasswordRequestFormWithHostname(OAuth2PasswordRequestForm):
    def __init__(
        self,
        *,
        username: Annotated[str, Form()],
        password: Annotated[str, Form()],
        hostname: Annotated[str, Form()],
        available_behaviours: Annotated[str | None, Form()] = None,
    ):
        super().__init__(
            username=username,
            password=password,
            scope="",
            client_id=None,
            client_secret=None,
        )
        self.hostname = hostname
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
    await websocket.send_json({"clients_info": [client for client in clients_info.values()]})


async def update_client_status(data, websocket):
    """Update client status"""
    # Status subscribers are read-only; inbound messages are ignored.
    pass


async def send_client_config(websocket, username):
    """Send client config to websocket"""

    pass


async def update_client_config(data, websocket, username):
    """Update client config"""
    # Implement your config update logic here
    pass


client_status_sockets = SocketManager(
    router,
    "/client_status_socket",
    True,
    send_client_status,
    update_client_status,
    auth_func=status_socket_auth,
)
client_sockets = SocketManager(router, "/client_socket", True, send_client_config, update_client_config)


async def broadcast_client_status():
    """Push the current client list to every connected status subscriber."""
    payload = {"clients_info": [client for client in clients_info.values()]}
    for websocket in list(client_status_sockets.connected_sockets.keys()):
        try:
            await websocket.send_json(payload)
        except Exception as ex:  # noqa: BLE001 - a dead subscriber must not abort the broadcast
            logging.warning(f"Dropping status subscriber, send failed: {ex}")
            client_status_sockets.connected_sockets.pop(websocket, None)


class ClientsInfoResponse(BaseModel):
    clients_info: list[ClientInfo]


@router.get(
    "/",
    response_model=ClientsInfoResponse,
    description="Get list of active clients, future status updates will be streamed via a websocket created like this:"
    "<br>`var socket = new WebSocket('ws://localhost:8000/client_status_socket');`",
    dependencies=[Depends(require_service_token)],
)
async def get_client_info() -> ClientInfo:
    return {"clients_info": [client for client in clients_info.values()]}


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
            "current_behaviour": None,
            "client_config": config_generator.generate_config(user["username"]),
            "hostname": form_data.hostname,
            "idle_cycle_active": None,
            "available_behaviours": form_data.available_behaviours,
        }
    else:
        clients_info[form_data.hostname]["hostname"] = form_data.hostname
        clients_info[form_data.hostname]["available_behaviours"] = form_data.available_behaviours

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


def get_reported_behaviours(username: str) -> set[str] | None:
    """Return the set of behaviours a user's connected client(s) reported as available.

    When the same user is connected from several hostnames the result is the
    intersection of every reported set, so the server only permits a behaviour
    that every target client can run. Returns None when no client for the user
    reported a set (unknown -> availability is not enforced).
    """
    reported_sets = [
        set(info["available_behaviours"])
        for info in clients_info.values()
        if info.get("username") == username and info.get("available_behaviours") is not None
    ]
    if not reported_sets:
        return None
    return set.intersection(*reported_sets)


@router.delete("/disconnect")
async def disconnect_client(hostname: str) -> dict:
    global clients_info
    if hostname in clients_info:
        del clients_info[hostname]
        await broadcast_client_status()
        return {"message": f"Client {hostname} disconnected"}
    else:
        raise HTTPException(status_code=404, detail="Client not found")
