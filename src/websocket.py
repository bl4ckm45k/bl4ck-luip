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
        self.token_refresh_attempts = 0  # Counter for token refresh attempts
        self.panel_address = config.marzban.host.split(':')[0]
        self.shutdown_event = asyncio.Event()
        self.active_tasks = []

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
            # Create tasks for each connection and track them
            self.active_tasks = [
                asyncio.create_task(self.connect_to_websocket(url, node_info))
                for url, node_info in self.connections
            ]
            
            # Wait for all tasks to complete or shutdown
            try:
                await asyncio.gather(*self.active_tasks, return_exceptions=True)
            except Exception as e:
                logger.error(f"Error in WebSocket connections: {e}", exc_info=True)

    async def connect_to_websocket(self, ws_url, node_info):
        """
        Connects to a WebSocket and processes messages with improved reconnection logic.
        
        Args:
            ws_url: WebSocket URL to connect to
            node_info: Dictionary with node information
        """
        reconnect_attempts = 0
        
        while not self.shutdown_event.is_set():
            try:
                async with websockets.connect(ws_url) as websocket:
                    logger.info(f"Connected to WebSocket: {node_info['address']}")
                    reconnect_attempts = 0  # Reset attempts on successful connection
                    self.token_refresh_attempts = 0  # Reset token refresh attempts
                    await self.handle_connection(websocket, node_info)
                    
            except ConnectionClosed as e:
                logger.warning(f"WebSocket connection closed for {node_info['address']}: {e}")
                reconnect_attempts += 1
                
                # Always try to reconnect, but refresh token periodically
                if reconnect_attempts % 10 == 0:  # Refresh token every 10 reconnection attempts
                    logger.warning(f"Refreshing token after {reconnect_attempts} reconnection attempts for {node_info['address']}")
                    await self.refresh_token()
                    # Rebuild connections with new token
                    nodes = await NodesRepository.get_all_nodes()
                    self.build_connections(nodes)
                    
            except InvalidStatusCode as e:
                logger.error(f"Invalid status code for {node_info['address']}: {e}")
                if e.status_code == 401:  # Unauthorized
                    logger.warning(f"Token expired for {node_info['address']}, refreshing...")
                    await self.refresh_token()
                    # Rebuild connections with new token
                    nodes = await NodesRepository.get_all_nodes()
                    self.build_connections(nodes)
                    reconnect_attempts = 0
                else:
                    reconnect_attempts += 1
                    
            except Exception as e:
                logger.error(f"Unexpected error connecting to {node_info['address']}: {e}", exc_info=True)
                reconnect_attempts += 1

            # Check if shutdown was requested
            if self.shutdown_event.is_set():
                logger.info(f"Shutdown requested, stopping connection to {node_info['address']}")
                break

            # Calculate backoff delay (exponential backoff with max limit)
            delay = min(self.reconnect_interval * (2 ** min(reconnect_attempts, 3)), 60)
            logger.info(f"Reconnecting to {node_info['address']} in {delay} seconds (attempt {reconnect_attempts + 1})")
            
            # Wait with timeout to check shutdown event periodically
            try:
                await asyncio.wait_for(self.shutdown_event.wait(), timeout=delay)
                break  # Shutdown was requested
            except asyncio.TimeoutError:
                continue  # Continue with reconnection

    def build_connections(self, nodes: Sequence[NodeResponse]):
        """
        Builds a list of WebSocket connections.
        
        Args:
            nodes: Sequence of node responses
        """
        # Clear existing connections
        self.connections.clear()
        
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
        try:
            async for message in websocket:
                # Check if shutdown was requested
                if self.shutdown_event.is_set():
                    logger.info(f"Shutdown requested, stopping message processing for {node_info['address']}")
                    break
                    
                await self.process_log(message, node_info)
        except ConnectionClosed:
            logger.warning(f"Connection closed during message processing for {node_info['address']}")
            raise  # Re-raise to trigger reconnection logic
        except Exception as e:
            logger.error(f"Error processing messages for {node_info['address']}: {e}", exc_info=True)
            raise  # Re-raise to trigger reconnection logic

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
            logger.debug(f"The ban operation for {email} is already in progress, skipping it")
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
        """Refreshes the authorization token with retry logic."""
        max_retries = 3
        retry_delay = 5
        
        for attempt in range(max_retries):
            try:
                self.access_token = await marz_token.get_token()
                logger.info("Token successfully refreshed")
                return
            except Exception as e:
                logger.error(f"Error refreshing token (attempt {attempt + 1}/{max_retries}): {e}", exc_info=True)
                if attempt < max_retries - 1:
                    logger.info(f"Retrying token refresh in {retry_delay} seconds...")
                    await asyncio.sleep(retry_delay)
                    retry_delay *= 2  # Exponential backoff
                else:
                    logger.error("Failed to refresh token after all attempts")
                    raise

    async def shutdown(self):
        """Gracefully shuts down the WebSocket service."""
        logger.info("Initiating graceful shutdown...")
        self.shutdown_event.set()
        
        # Cancel all active tasks
        for task in self.active_tasks:
            if not task.done():
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass
        
        logger.info("WebSocket service shutdown complete")


def main():
    """Main entry point for WsService when run directly."""
    from logger import log_manager
    import signal

    # Configure logging
    log_manager.configure(log_level=logging.INFO)
    logger.info("Starting WebSocket service")

    # Create service instance
    service = WsService()
    
    def signal_handler(signum, frame):
        logger.info(f"Received signal {signum}, shutting down gracefully...")
        # Schedule shutdown in the event loop
        asyncio.create_task(service.shutdown())
    
    # Register signal handlers for graceful shutdown
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    try:
        asyncio.run(service.start())
    except KeyboardInterrupt:
        logger.info("WebSocket service stopped by user")
    except Exception as e:
        logger.error(f"WebSocket service failed: {e}", exc_info=True)
    finally:
        # Ensure graceful shutdown
        if not service.shutdown_event.is_set():
            asyncio.run(service.shutdown())


if __name__ == '__main__':
    main()
