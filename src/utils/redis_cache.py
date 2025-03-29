"""
Redis caching and helper functions for optimizing Redis operations.
"""
import json
from typing import Any, Dict, List, Optional, TypeVar, Callable, Set

from loader import redis_cli, config
from logger import get_logger

# Get logger for this module
logger = get_logger(__name__)

T = TypeVar('T')

# Default cache TTL settings (in seconds)
DEFAULT_CACHE_TTL = 1800  # 30 minutes
DEFAULT_CONNECTION_TTL = config.settings.ban_seconds * 2
DEFAULT_BAN_TTL = config.settings.ban_seconds


class RedisCache:
    """
    Centralized class for Redis caching management.
    Provides methods for cache operations and optimized 
    functions for frequently used patterns.
    """

    @staticmethod
    async def get_cached_item(key: str, serializer: Callable[[Dict], T] = None) -> Optional[T]:
        """
        Gets an item from cache.
        
        Args:
            key: Cache key
            serializer: Function for deserializing data
            
        Returns:
            Deserialized object or None if item not found
        """
        data = await redis_cli.get(key)
        if not data:
            return None

        if serializer:
            return serializer(json.loads(data))
        return json.loads(data)

    @staticmethod
    async def set_cached_item(key: str, value: Any, ttl: int = DEFAULT_CACHE_TTL) -> bool:
        """
        Saves an item to cache.
        
        Args:
            key: Cache key
            value: Value to save (will be serialized to JSON)
            ttl: Cache time-to-live in seconds
            
        Returns:
            True if operation completed successfully
        """
        try:
            serialized = json.dumps(value)
            await redis_cli.set(key, serialized, ex=ttl)
            return True
        except Exception as e:
            logger.error(f"Error caching item {key}: {e}", exc_info=True)
            return False

    @staticmethod
    async def invalidate_cache(*keys: str) -> int:
        """
        Invalidates cache for specified keys.
        
        Args:
            keys: Keys to invalidate
            
        Returns:
            Number of deleted keys
        """
        if not keys:
            return 0

        return await redis_cli.delete(*keys)

    @staticmethod
    async def invalidate_pattern(pattern: str) -> int:
        """
        Invalidates cache by pattern.
        
        Args:
            pattern: Key pattern to invalidate
            
        Returns:
            Number of deleted keys
        """
        keys = await redis_cli.keys(pattern)
        if not keys:
            return 0

        return await redis_cli.delete(*keys)

    @staticmethod
    async def batch_get(keys: List[str]) -> List[Optional[Any]]:
        """
        Gets multiple items from cache in a single request.

        Args:
            keys: List of keys

        Returns:
            List of values
        """
        pipe = redis_cli.pipeline()
        for key in keys:
            pipe.get(key)

        results = await pipe.execute()

        deserialized_results = []
        for r in results:
            if not r:
                deserialized_results.append(None)
            else:
                try:
                    deserialized_results.append(json.loads(r))
                except json.JSONDecodeError as e:
                    logger.warning(f"Failed to deserialize cache value: {e}")
                    deserialized_results.append(None)

        return deserialized_results

    @staticmethod
    async def batch_set(items: Dict[str, Any], ttl: int = DEFAULT_CACHE_TTL) -> bool:
        """
        Saves multiple items to cache in a single request.

        Args:
            items: Dictionary {key: value}
            ttl: Cache time-to-live in seconds

        Returns:
            True if operation completed successfully
        """
        if not items:
            return True

        pipe = redis_cli.pipeline()
        serialization_errors = []

        for key, value in items.items():
            try:
                serialized = json.dumps(value)
                pipe.set(key, serialized, ex=ttl)
            except (TypeError, ValueError) as e:
                serialization_errors.append((key, str(e)))
                logger.error(f"Failed to serialize value for key {key}: {e}")

        if serialization_errors:
            logger.warning(f"Skipped {len(serialization_errors)} items due to serialization errors")

        if pipe._pipeline:
            await pipe.execute()

        return len(serialization_errors) == 0

    @staticmethod
    async def increment_counter(key: str, amount: int = 1, ttl: int = DEFAULT_CACHE_TTL) -> int:
        """
        Increments a counter and sets expiration time.
        
        Args:
            key: Counter key
            amount: Increment amount
            ttl: Time-to-live in seconds
            
        Returns:
            New counter value
        """
        pipe = redis_cli.pipeline()
        pipe.incrby(key, amount)
        pipe.expire(key, ttl)
        results = await pipe.execute()
        return results[0]

    @staticmethod
    async def track_ip_connection(email: str, ip: str, ttl: int = DEFAULT_CONNECTION_TTL) -> int:
        """
        Tracks IP connection for a specified user.
        
        Args:
            email: User's email
            ip: IP address
            ttl: Record time-to-live
            
        Returns:
            Number of unique IPs for this email
        """
        connections_key = f"connections:{email}"

        pipe = redis_cli.pipeline()
        pipe.sadd(connections_key, ip)
        pipe.expire(connections_key, ttl)
        pipe.scard(connections_key)
        results = await pipe.execute()

        return results[2]  # Number of IPs

    @staticmethod
    async def get_ip_connections_count(email: str) -> int:
        """
        Gets the number of unique IPs for a user.
        
        Args:
            email: User's email
            
        Returns:
            Number of unique IPs
        """
        return await redis_cli.scard(f"connections:{email}")

    @staticmethod
    async def get_ip_connections(email: str) -> Set[str]:
        """
        Gets a list of unique IPs for a user.
        
        Args:
            email: User's email
            
        Returns:
            List of IP addresses
        """
        return await redis_cli.smembers(f"connections:{email}")

    @staticmethod
    async def ban_ip(node_address: str, ip: str, ttl: int = DEFAULT_BAN_TTL) -> bool:
        """
        Bans an IP address on the specified node.
        
        Args:
            node_address: Node address
            ip: IP address
            ttl: Ban duration in seconds
            
        Returns:
            True if operation completed successfully
        """
        logger.debug(f"Banning IP {ip} on node {node_address} for {ttl} seconds")
        await redis_cli.set(f"banned:{node_address}:{ip}", "t", ex=ttl)
        return True

    @staticmethod
    async def is_ip_banned(node_address: str, ip: str) -> bool:
        """
        Checks if an IP address is banned on the specified node.
        
        Args:
            node_address: Node address
            ip: IP address
            
        Returns:
            True if IP is banned
        """
        result = bool(await redis_cli.exists(f"banned:{node_address}:{ip}"))
        if result:
            logger.debug(f"IP {ip} is already banned on node {node_address}")
        return result

    @staticmethod
    async def unban_ip(node_address: str, ip: str) -> bool:
        """
        Unbans an IP address on the specified node.
        
        Args:
            node_address: Node address
            ip: IP address
            
        Returns:
            True if operation completed successfully
        """
        logger.debug(f"Unbanning IP {ip} on node {node_address}")
        await redis_cli.delete(f"banned:{node_address}:{ip}")
        return True

    @staticmethod
    async def batch_unban_ips(node_address: str, ips: List[str]) -> int:
        """
        Unbans multiple IP addresses on the specified node in a single request.
        
        Args:
            node_address: Node address
            ips: List of IP addresses
            
        Returns:
            Number of unbanned IPs
        """
        if not ips:
            return 0

        logger.debug(f"Batch unbanning {len(ips)} IPs on node {node_address}")
        keys = [f"banned:{node_address}:{ip}" for ip in ips]
        return await redis_cli.delete(*keys)


# Create a global instance for use in other modules
redis_cache = RedisCache()
