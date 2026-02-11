import logging
import os
import time
from typing import Annotated

import yaml
from fastapi import APIRouter, Depends, Form, HTTPException
from fastapi.security import OAuth2PasswordRequestForm
from jose import jwt
from pydantic import BaseModel

# from auth import current_user
from config_generator import ConfigGenerator
from hostname import is_valid_hostname
from models.client_config import ClientConfig
from parse_credentials import parse_user_credentials
from sockets import SocketManager

# Load configuration from environment variables or a file
JWT_SECRET = os.getenv("JWT_SECRET", "ExgEFKuRnzSZhjAq")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
JWT_EXPIRATION = int(os.getenv("JWT_EXPIRATION", 36000))  # seconds


class ClientInfo(BaseModel):
    username: str
    hostname: str
    current_behaviour: str | None
    client_config: ClientConfig


class OAuth2PasswordRequestFormWithHostname(OAuth2PasswordRequestForm):
    def __init__(
        self,
        *,
        username: Annotated[str, Form()],
        password: Annotated[str, Form()],
        hostname: Annotated[str, Form()],
    ):
        super().__init__(
            username=username,
            password=password,
            scope="",
            client_id=None,
            client_secret=None,
        )
        self.hostname = hostname


cwd = os.path.abspath(os.path.dirname(__file__))
config_file = os.path.join(cwd, "config.yml")
user_credentials_file = os.path.join(cwd, "user_credentials.yml")
config_generation_file = os.path.join(cwd, "config_generator.yml")

exchange_credentials, domain_credentials = parse_user_credentials(user_credentials_file)
available_client_users = {user["username"]: user for user in (exchange_credentials + domain_credentials)}

clients_info: dict[str, ClientInfo] = {}

config_generator = None

with open(config_generation_file, "r") as stream:
    config_generator = ConfigGenerator(yaml.safe_load(stream).get("config_generation", {}))

router = APIRouter()


async def send_client_status(websocket):
    """Send client status updates to websocket"""
    # Implement your status sending logic here
    pass


async def update_client_status(data, websocket):
    """Update client status"""
    # Implement your status update logic here
    pass


async def send_client_config(websocket, username):
    """Send client config to websocket"""

    pass


async def update_client_config(data, websocket, username):
    """Update client config"""
    # Implement your config update logic here
    pass


client_status_sockets = SocketManager(router, "/client_status_socket", True, send_client_status, update_client_status)
client_sockets = SocketManager(router, "/client_socket", True, send_client_config, update_client_config)


class ClientsInfoResponse(BaseModel):
    clients_info: list[ClientInfo]


@router.get(
    "/",
    response_model=ClientsInfoResponse,
    description="Get list of active clients, future status updates will be streamed via a websocket created like this:"
    "<br>`var socket = new WebSocket('ws://localhost:8000/client_status_socket');`",
)
async def get_client_info(
    # username: str = Depends(current_user),
) -> ClientInfo:
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
        form_data.username in available_client_users
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
        }
    else:
        clients_info[form_data.hostname]["hostname"] = form_data.hostname

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


@router.delete("/disconnect")
async def disconnect_client(hostname: str) -> dict:
    global clients_info
    if hostname in clients_info:
        del clients_info[hostname]
        return {"message": f"Client {hostname} disconnected"}
    else:
        raise HTTPException(status_code=404, detail="Client not found")
