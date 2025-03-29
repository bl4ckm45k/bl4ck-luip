import asyncio
import logging
import re
from typing import Sequence
from urllib.parse import urlencode

import websockets
from websockets.exceptions import ConnectionClosed, InvalidStatusCode

from db.repository import NodesRepository
from db.schemas import NodeResponse
from loader import config, marz_token, redis_cli
from logger import get_logger
from utils.manager import ban_ip
from utils.redis_cache import redis_cache

# Get logger for this module
logger = get_logger(__name__)


class WsService:
    def __init__(self):
        self.access_token = ''
        self.connections = []  # List of tuples (url, node_info)
        self.reconnect_interval = 10  # Reconnection interval (seconds)
        self.panel_address = config.marzban.host.split(':')[0]

    async def start(self):
        """Starts the WebSocket connection process."""
        await self.refresh_token()
        await self.connect_with_token()

    async def connect_with_token(self):
        """Connects to WebSockets using the access token."""
        if not self.access_token:
            logger.info('Token is missing, refreshing...')
            await self.refresh_token()

        nodes = await NodesRepository.get_all_nodes()
        self.build_connections(nodes)

        if self.connections:
            await asyncio.gather(*[self.connect_to_websocket(url, node_info) for url, node_info in self.connections])

    async def connect_to_websocket(self, ws_url, node_info):
        """
        Connects to a WebSocket and processes messages.
        
        Args:
            ws_url: WebSocket URL to connect to
            node_info: Dictionary with node information
        """
        while True:
            try:
                async with websockets.connect(ws_url) as websocket:
                    logger.info(f"Connected to WebSocket: {node_info['address']}")
                    await self.handle_connection(websocket, node_info)
            except (ConnectionClosed, InvalidStatusCode):
                logger.warning(f"Lost connection to {node_info['address']}. Reconnecting...")
                await self.refresh_token()
            except Exception as e:
                logger.error(f"Error connecting to {node_info['address']}: {e}", exc_info=True)

            await asyncio.sleep(self.reconnect_interval)

    def build_connections(self, nodes: Sequence[NodeResponse]):
        """
        Builds a list of WebSocket connections.
        
        Args:
            nodes: Sequence of node responses
        """
        protocol = 'wss://' if config.settings.ssl_enabled else 'ws://'
        query_params = urlencode({'interval': 5, 'token': self.access_token})

        for node in nodes:
            if node.is_core:
                self.connections.append(
                    (f"{protocol}{config.marzban.host}/api/core/logs?{query_params}",
                     {'id': node.node_id, 'address': node.node_address})
                )
            else:
                self.connections.append(
                    (f"{protocol}{config.marzban.host}/api/node/{node.id}/logs?{query_params}",
                     {'id': node.node_id, 'address': node.node_address}))

    async def handle_connection(self, websocket, node_info):
        """
        Handles WebSocket connection and processes incoming messages.
        
        Args:
            websocket: WebSocket connection object
            node_info: Dictionary with node information
        """
        async for message in websocket:
            await self.process_log(message, node_info)

    async def process_log(self, log, node_info):
        """
        Processes logs, extracts IP and email.
        
        Args:
            log: Log message to process
            node_info: Dictionary with node information
        """
        match = re.search(r'(?P<ip>\d{1,3}(?:\.\d{1,3}){3}):\d{1,5}.*email:\s*(?P<email>\S+)', log)
        if match:
            ip, email = match.group('ip'), match.group('email')
            logger.info(f'Connection to node: {node_info["address"]} | User: {email} | IP: {ip}')

            # Check if IP is already banned
            is_banned = await redis_cache.is_ip_banned(node_info['address'], ip)
            if is_banned:
                logger.debug(f"IP {ip} is already banned, skipping")
                return

            # Track connection and get unique IP count
            connections_count = await redis_cache.track_ip_connection(
                email=email,
                ip=ip,
                ttl=config.settings.ban_seconds
            )

            if connections_count > config.settings.max_connections:
                logger.warning(f"Connection limit exceeded for user {email} ({connections_count} IPs)")
                await self.ban_excess_ips(email, node_info)

    async def ban_excess_ips(self, email, node_info):
        """
        Bans IP addresses if the number of connections exceeds the maximum.
        
        Args:
            email: User's email
            node_info: Dictionary with node information
        """
        # Get list of IPs for this user
        current_ips = await redis_cache.get_ip_connections(email)

        # Sort IPs (optional, can use different logic)
        sorted_ips = sorted(current_ips)

        # Keep only those IPs that need to be banned
        ips_to_ban = sorted_ips[config.settings.max_connections:]

        if not ips_to_ban:
            logger.debug(f"No IPs to ban for user {email}")
            return

            # Получаем уникальный ключ для этой операции бана (для предотвращения дублирования логов)
        ban_operation_key = f"ban_operation:{email}:{','.join(ips_to_ban)}"

        # Проверяем, не выполняется ли уже операция бана
        if await redis_cache.get(ban_operation_key):
            logger.debug(f"Операция бана для {email} уже выполняется, пропускаем")
            return

        # Устанавливаем флаг, что операция бана началась (с коротким TTL)
        await redis_cli.set(ban_operation_key, 1, ex=config.settings.ban_seconds - 30)

        logger.info(f"Preparing to ban {len(ips_to_ban)} IPs for user {email}")

        # Check which IPs are already banned
        check_tasks = []
        for ip in ips_to_ban:
            check_tasks.append(redis_cache.is_ip_banned(node_info['address'], ip))

        ban_results = await asyncio.gather(*check_tasks)

        # Ban only unbanned IPs
        ban_tasks = []
        for idx, ip in enumerate(ips_to_ban):
            if not ban_results[idx]:
                logger.warning(f"The number of connections has exceeded the limit for {email}, {ip} is being banned")
                # Add ban task
                ban_tasks.append(
                    asyncio.create_task(
                        ban_ip(
                            self.panel_address if node_info['address'] == 'Panel' else node_info['address'],
                            ip,
                            email
                        )
                    )
                )

        # Execute all ban tasks in parallel
        if ban_tasks:
            await asyncio.gather(*ban_tasks)
            logger.info(f"Successfully banned {len(ban_tasks)} IPs for user {email}")

    async def refresh_token(self):
        """Refreshes the authorization token."""
        try:
            self.access_token = await marz_token.get_token()
            logger.info("Token successfully refreshed")
        except Exception as e:
            logger.error(f"Error refreshing token: {e}", exc_info=True)


def main():
    """Main entry point for WsService when run directly."""
    from logger import log_manager

    # Configure logging
    log_manager.configure(log_level=logging.INFO)
    logger.info("Starting WebSocket service")

    asyncio.run(WsService().start())


if __name__ == '__main__':
    main()
