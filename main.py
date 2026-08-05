import configparser
import logging
import os

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from auth import router as auth_router
from client import router as client_router
from client_behaviour import router as behaviour_router
from i18n import I18nMiddleware
from screenshot import router as screenshot_router

config = configparser.ConfigParser()
config.read(os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.ini"))
logging.basicConfig(
    level=config["DEFAULT"]["log_level"],
    filename=config["DEFAULT"]["log_file"],
    filemode="a",
    format="%(asctime)s : %(levelname)s : %(message)s",
)

origins = config["DEFAULT"]["allowed_origins"].split("\n")
app = FastAPI(title=config["DEFAULT"]["title"], version=config["DEFAULT"]["version"])
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.add_middleware(I18nMiddleware)

app.include_router(auth_router)
app.include_router(client_router, prefix="/client", tags=["Client"])
app.include_router(behaviour_router, prefix="/client_behaviour", tags=["Client Behaviour"])
app.include_router(screenshot_router, prefix="/screenshot", tags=["Screenshot"])

logging.info(f"Started {config['DEFAULT']['title']} server {config['DEFAULT']['version']}")


@app.middleware("http")
async def log_requests(request, call_next):
    response = await call_next(request)
    logging.info(f"{request.method} {request.url}, {response.status_code}")
    return response
