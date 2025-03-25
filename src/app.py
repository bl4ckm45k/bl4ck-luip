import asyncio
import logging
from contextlib import asynccontextmanager

import betterlogging as bl
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware

from db.database import engine
from db.models import Base
from routes.admin import setup_admin
from utils.manager import unban_expired, load_nodes
from websocket import WsService


@asynccontextmanager
async def lifespan(app: FastAPI):

    logging.info(f'Starting web app')
    await load_nodes()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
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


def setup_logging():
    log_level = logging.INFO
    bl.basic_colorized_config(level=log_level)

    logging.basicConfig(
        level=log_level,
        format="%(filename)s:%(lineno)d #%(levelname)-8s [%(asctime)s] - %(name)s - %(message)s",
    )
    # logging.getLogger(__name__)
    logging.getLogger("httpcore.http11").setLevel(logging.ERROR)
    logging.getLogger("httpx").setLevel(logging.ERROR)
    logging.getLogger("websockets.client").setLevel(logging.INFO)
    logging.getLogger("paramiko.transport").setLevel(logging.ERROR)


app = FastAPI(lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["POST", "GET"],
    allow_headers=["*"],
)

app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=[
        "*",
        "*"
    ]
)

if __name__ == "__main__":
    import uvicorn

    setup_logging()
    uvicorn.run(app, host="0.0.0.0", port=7767)
