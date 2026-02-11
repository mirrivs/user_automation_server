import logging
import os
import time
from typing import Annotated, Awaitable, Optional

from fastapi import APIRouter, Depends, HTTPException, WebSocket
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm  # , JWTAuthentication
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel

from utils import WSMessage

router = APIRouter()

# Load configuration from environment variables or a file
JWT_SECRET = os.getenv("JWT_SECRET", "ExgEFKuRnzSZhjAq")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
JWT_EXPIRATION = int(os.getenv("JWT_EXPIRATION", 36000))  # seconds

users = {
    "blue01": {
        "id": 2,
        "username": "blue01",
        "full_name": "Blue Team 01",
        "email": "blue01@kyberakademia.sk",
        "password": "$2b$12$jbFuj4c/QVuQ0o73VhEh.OFjTBMtFWpcsDuh3fw19dF.rAQ.29md2",
        "team": "blue",
        "disabled": False,
    },
    "blue02": {
        "id": 3,
        "username": "blue02",
        "full_name": "Blue Team 02",
        "email": "blue02@kyberakademia.sk",
        "password": "$2b$12$Km3NXERRM5t1C46PUWPJFule5n6wECHBwoPRRBIMlASMg.tuFC59i",
        "team": "blue",
        "disabled": False,
    },
    "red01": {
        "id": 4,
        "username": "red01",
        "full_name": "Red Team 01",
        "email": "red01@kyberakademia.sk",
        "password": "$2b$12$656KFjOPXWnjVRBZ7nXysOQ7L/V1N7YeqzF49/59N9Y.w6TSAz1e6",
        "team": "red",
        "disabled": False,
    },
    "red02": {
        "id": 5,
        "username": "red02",
        "full_name": "Red Team 02",
        "email": "red02@kyberakademia.sk",
        "password": "$2b$12$DC/XRk9iB46VlPBsPIbvEOH9MOKhkIOK1VYvfYqEksgUzu7CsxVzW",
        "team": "red",
        "disabled": False,
    },
    "green01": {
        "id": 6,
        "username": "green01",
        "full_name": "Green Team 01",
        "email": "green01@kyberakademia.sk",
        "password": "$2b$12$PUeuWguMACxkcCOP3mmIl.aMe5F9yNNUk7togBfnG64VrmNAt4Qzi",
        "team": "green",
        "disabled": False,
    },
    "green02": {
        "id": 7,
        "username": "green02",
        "full_name": "Green Team 02",
        "email": "green02@kyberakademia.sk",
        "password": "$2b$12$yXWNzKk802RhROOOUIsuReFc4ggtmcQ4L6kwNZhVgGGelHhhL0/ym",
        "team": "green",
        "disabled": False,
    },
    "white01": {
        "id": 8,
        "username": "white01",
        "full_name": "White Team 01",
        "email": "white01@kyberakademia.sk",
        "password": "$2b$12$68Gii5Rg/4gp7Tcn0SQlQOnFw4l5ZgkG6MYmR/QmvRVq/qnNqFsU6",
        "team": "white",
        "disabled": False,
    },
    "white02": {
        "id": 9,
        "username": "white02",
        "full_name": "White Team 02",
        "email": "white02@kyberakademia.sk",
        "password": "$2b$12$xNQpQ33u3W4LY0VcGCiNV.xSJ.jqn/2TVRQ18/WX3ze138k0AHfZ6",
        "team": "white",
        "disabled": False,
    },
}


# Set up authentication
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")
# jwt_authentication = JWTAuthentication(secret=JWT_SECRET, algorithm=JWT_ALGORITHM)


async def current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        username = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="errors.invalid_auth_token")
        return username
    except JWTError as e:
        raise HTTPException(status_code=401, detail="errors.invalid_auth_token") from e


class User(BaseModel):
    id: int
    username: str
    email: str
    team: str
    full_name: str
    disabled: bool
    team_title: Optional[str] = None


class LoginResponse(BaseModel):
    access_token: str
    token_type: str
    user: User


@router.post("/login", response_model=LoginResponse, tags=["Authentication"])
async def login(form_data: Annotated[OAuth2PasswordRequestForm, Depends()]):
    """
    Authenticate a user and generate a JWT token
    """
    # Verify username and password against the users from elasticsearch
    if not (
        form_data.username in users and pwd_context.verify(form_data.password, users[form_data.username]["password"])
    ):
        logging.warning(f"Invalid login attempt from user {form_data.username}")
        raise HTTPException(status_code=401, detail="errors.invalid_username_or_password")
    logging.info(f"User {form_data.username} logged in")

    current_user = users[form_data.username]

    # Generate JWT token
    token = jwt.encode(
        {"sub": current_user["username"], "exp": int(time.time()) + JWT_EXPIRATION},
        JWT_SECRET,
        algorithm=JWT_ALGORITHM,
    )

    return {"access_token": token, "token_type": "bearer", "user": current_user}


@router.get("/current_user", response_model=User, tags=["Authentication"])
async def get_current_user(username: str = Depends(current_user)):
    """
    Get details of the current user
    """
    return users.get(username)


async def authenticate_ws_user(websocket: WebSocket) -> Awaitable[Optional[User]]:
    token = await websocket.receive_text()
    try:
        return users.get(await current_user(token))
    except HTTPException:
        status_msg = WSMessage.status("Invalid token")
        await websocket.send_json(status_msg.dict())
        await websocket.close()
        return None
