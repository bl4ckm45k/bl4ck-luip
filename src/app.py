import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware

from loader import config
from logger import get_logger
from routes.admin import setup_admin
from utils.manager import unban_expired, load_nodes
from websocket import WsService

# Get logger for this module
logger = get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info('Starting web application')
    await load_nodes()
    _loop = asyncio.get_running_loop()
    _loop.call_later(1, repeat_unban)
    setup_admin(app)
    ws = WsService()
    asyncio.create_task(ws.start())
    yield


def repeat_unban():
    _loop = asyncio.get_running_loop()
    asyncio.ensure_future(unban_expired(), loop=_loop)
    _loop.call_later(60, repeat_unban)



app = FastAPI(lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=config.settings.allowed_hosts,
    allow_credentials=True,
    allow_methods=["POST", "GET"],
    allow_headers=["*"],
)

app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=config.settings.allowed_hosts
)

if __name__ == "__main__":
    import uvicorn

    logging.info(f"Starting server with hosts: {config.settings.allowed_hosts}")
    uvicorn.run(app, host="0.0.0.0", port=17767)
