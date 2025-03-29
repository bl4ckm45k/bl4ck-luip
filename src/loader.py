import sys

import redis.asyncio as redis
from marzban import MarzbanAPI

from config import load_config
from logger import log_manager
from utils.marz_client import MarzTokenCache

log_manager.setup_from_config(environment='production')
config = load_config()

if sys.platform == 'win32':
    redis_cli = redis.Redis(decode_responses=True)
else:
    redis_cli = redis.Redis(
        host=config.redis.redis_host,
        port=config.redis.redis_port,
        password=config.redis.redis_pass,
        decode_responses=True)
marzban_url = f"{'https://' if config.settings.ssl_enabled else 'http://'}{config.marzban.host}"
api = MarzbanAPI(base_url=marzban_url)
marz_token = MarzTokenCache(api, config)
