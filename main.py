import logging
import configparser

from fastapi import FastAPI

from fastapi.middleware.cors import CORSMiddleware
from i18n import I18nMiddleware

from auth import router as auth_router
from clients import router as clients_router

config = configparser.ConfigParser()
config.read("config.ini")
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
app.include_router(clients_router)

logging.info(
    f"Started {config['DEFAULT']['title']} server {config['DEFAULT']['version']}"
)


@app.middleware("http")
async def log_requests(request, call_next):
    response = await call_next(request)
    logging.info(f"{request.method} {request.url}, {response.status_code}")
    return response
