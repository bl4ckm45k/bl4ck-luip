import asyncio
import logging
import re
from urllib.parse import urlencode

import websockets
from websockets.exceptions import ConnectionClosed, InvalidStatusCode

from loader import api, redis_cli, config, marz_token
from utils.manager import ban_ip

logging.getLogger(__name__)

class WsService:
    def __init__(self):
        self.access_token = ''
        self.connections = []  # Список кортежей (url, node_info)
        self.reconnect_interval = 10  # Интервал переподключения (секунды)
        self.panel_address = config.marzban.host.split(':')[0]

    async def start(self):
        """Запускает процесс подключения к WebSocket."""
        await self.refresh_token()
        await self.connect_with_token()

    async def connect_with_token(self):
        if not self.access_token:
            logging.info('Токен отсутствует, обновляем...')
            await self.refresh_token()

        nodes = await api.get_nodes(self.access_token)
        self.build_connections(nodes)

        if self.connections:
            await asyncio.gather(*[self.connect_to_websocket(url, node_info) for url, node_info in self.connections])

    async def connect_to_websocket(self, ws_url, node_info):
        """Подключается к WebSocket и обрабатывает сообщения."""
        while True:
            try:
                async with websockets.connect(ws_url) as websocket:
                    logging.info(f"Подключено к WebSocket: {node_info['address']}")
                    await self.handle_connection(websocket, node_info)
            except (ConnectionClosed, InvalidStatusCode):
                logging.warning(f"Потеряно соединение с {node_info['address']}. Переподключение...")
                await self.refresh_token()
            except Exception as e:
                logging.error(f"Ошибка при подключении к {node_info['address']}: {e}", exc_info=True)

            await asyncio.sleep(self.reconnect_interval)

    def build_connections(self, nodes):
        """Формирует список WebSocket подключений."""
        protocol = 'wss://' if config.settings.ssl_enabled else 'ws://'
        query_params = urlencode({'interval': 5, 'token': self.access_token})

        self.connections = [
            (f"{protocol}{config.marzban.host}/api/node/{node.id}/logs?{query_params}",
             {'id': node.id, 'address': node.address})
            for node in nodes
        ]

        if config.settings.read_panel:
            self.connections.append(
                (f"{protocol}{config.marzban.host}/api/core/logs?{query_params}",
                 {'id': 'core', 'address': 'Panel'})
            )

    async def handle_connection(self, websocket, node_info):
        async for message in websocket:
            await self.process_log(message, node_info)

    async def process_log(self, log, node_info):
        """Обрабатывает логи, извлекает IP и email."""
        match = re.search(r'(?P<ip>\d{1,3}(?:\.\d{1,3}){3}):\d{1,5}.*email:\s*(?P<email>\S+)', log)
        if match:
            ip, email = match.group('ip'), match.group('email')
            logging.info(f'Connection to node: {node_info["address"]} | User: {email} | IP: {ip}')

            connections_key = f"connections:{email}"
            current_ips = await redis_cli.smembers(connections_key)
            if not current_ips or ip not in current_ips:
                logging.info(f'{ip} not in connections list for user {email}')
                await redis_cli.sadd(connections_key, ip)
                await redis_cli.expire(connections_key, config.settings.ban_seconds)

            if await redis_cli.scard(connections_key) > config.settings.max_connections:
                await self.ban_excess_ips(email, current_ips, node_info)

    async def ban_excess_ips(self, email, current_ips, node_info):
        """Блокирует IP-адреса, если превышено допустимое количество подключений."""
        for i, ip in enumerate(current_ips, start=1):
            if i <= config.settings.max_connections:
                continue
            if await redis_cli.get(f"banned:{node_info['address']}:{ip}"):
                continue
            logging.info(f"Превышено количество подключений для {email}, блокируем IP {ip}")
            if not await redis_cli.get(f"banned:{node_info['address']}:{ip}"):
                await ban_ip(self.panel_address if node_info['address'] == 'Panel' else node_info['address'], ip, email)
            await redis_cli.srem(f"connections:{email}", ip)

    async def refresh_token(self):
        """Обновляет токен авторизации."""
        try:
            self.access_token = await marz_token.get_token()
            logging.info("Токен успешно обновлен")
        except Exception as e:
            logging.error(f"Ошибка при обновлении токена: {e}")


def main():
    asyncio.run(WsService().start())


if __name__ == '__main__':
    main()