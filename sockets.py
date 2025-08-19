import copy
import json
import asyncio
import logging

from utils import WSMessage
from datetime import datetime
from fastapi import APIRouter, WebSocket, HTTPException, WebSocketDisconnect

from auth import current_user


class CustomJSONEncoder(json.JSONEncoder):
    def default(self, obj):
        return obj.isoformat() if isinstance(obj, datetime) else super().default(obj)


class SocketManager:
    def __init__(
        self,
        router: APIRouter,
        endpoint: str,
        is_json: bool,
        connect_func=None,
        receive_func=None,
    ):
        self.connected_sockets: dict[WebSocket, str] = (
            {}
        )  # store connected websockets for event updates
        self.router = router
        self.is_json = is_json

        @router.websocket(endpoint)
        async def websocket_endpoint(websocket: WebSocket):
            await websocket.accept()
            token = await websocket.receive_text()  # receive auth token as first message
            try:
                username = await current_user(token)
            except HTTPException:
                logging.warning(f"Socket {endpoint} attempted connect with invalid token {token}")
                await self._update_status("Invalid token", websocket)
                await websocket.close()
                return
            logging.info(f"Socket {endpoint} connected for user {username}")
            await self._update_status("Connected to socket", websocket)
            self.connected_sockets[websocket] = username
            if connect_func:
                await connect_func(websocket, username)

            # receive message from client
            try:
                while True:
                    if receive_func:
                        if self.is_json:
                            try:
                                received_message = await websocket.receive_json()
                            except json.JSONDecodeError:
                                logging.warning(f"Socket {endpoint} for user {username} received invalid JSON message")
                                await self._update_status("Invalid message JSON", websocket)
                                continue
                        else:
                            received_message = await websocket.receive_text()
                        logging.info(f"Socket {endpoint} for user {username} received message {received_message}")
                        await receive_func(received_message, websocket, username)
                    else:
                        # Just keep the connection alive without custom processing
                        received_message = await websocket.receive_json()
                        logging.info(f"Socket {endpoint} for user {username} received message {received_message}")
            
            except (WebSocketDisconnect, asyncio.CancelledError):
                logging.info(f"Socket {endpoint} for user {username} disconnected normally")
            except RuntimeError as ex:
                logging.info(f"Socket {endpoint} for user {username} disconnected with RuntimeError: {ex}")
            except Exception as ex:
                logging.error(f"Socket {endpoint} for user {username} encountered unexpected error: {ex}")
            finally:
                if websocket in self.connected_sockets:
                    del self.connected_sockets[websocket]
                logging.info(f"Socket {endpoint} for user {username} cleaned up")

    async def send_to_all(self, message):
        sockets = list(self.connected_sockets.keys())
        for ws in sockets:
            await self._send_message(message, ws)

    async def send_to_user(self, message, websocket: WebSocket):
        await self._send_message(message, websocket)

    async def _update_status(self, status: str, websocket: WebSocket):
        if self.is_json:
            status_msg = WSMessage.status(status)
            await websocket.send_json(status_msg.dict())
        else:
            await websocket.send_text(status)

    async def _send_message(self, message: str, ws: WebSocket):
        try:
            if self.is_json:
                if isinstance(message, object):
                    await ws.send_text(
                        json.dumps(
                            WSMessage.object_message(message).dict(),
                            cls=CustomJSONEncoder,
                        )
                    )
                else:
                    await ws.send_text(json.dumps(message, cls=CustomJSONEncoder))
            else:
                await ws.send_text(message)
        except RuntimeError:
            logging.warning(f"Socket {ws} is closed, cannot send message")
            del self.connected_sockets[ws]
