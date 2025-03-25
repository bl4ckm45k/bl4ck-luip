import logging
from datetime import datetime, timedelta
from typing import Optional

from marzban import MarzbanAPI

logging.getLogger(__name__)


class MarzTokenCache:
    def __init__(self, client: MarzbanAPI, config):
        self._client = client
        self._exp_at: Optional[datetime] = None
        self._config = config
        self._token: str = ''

    async def get_token(self):
        if not self._exp_at or self._exp_at < datetime.now():
            logging.info(f'Get new token')
            self._token = await self.get_new_token()
            self._exp_at = datetime.now() + timedelta(minutes=self._config.marzban.token_lifetime - 1)
        return self._token

    async def get_new_token(self):
        try:
            token = await self._client.get_token(
                username=self._config.marzban.login,
                password=self._config.marzban.password
            )
            return token.access_token
        except Exception as e:
            logging.error(f'{e}', exc_info=True)
            raise
