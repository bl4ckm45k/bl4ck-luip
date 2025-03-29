import json
from datetime import datetime
from typing import Optional, Sequence

from sqlalchemy import select, delete
from sqlalchemy.exc import IntegrityError

from loader import redis_cli
from .database import async_session
from .models import BannedIP, Node
from .schemas import BanCreate, BanResponse, NodeBase, NodeResponse


class BaseRepository:
    model = None

    @classmethod
    async def get_all(cls):
        """
        Retrieves all records of the model.
        
        Returns:
            Sequence of all model instances
        """
        query = select(cls.model)
        async with async_session() as session:
            result = await session.execute(query)
        return result.scalars().all()

    @classmethod
    async def get_by_id(cls, _id: int) -> Optional[object]:
        """
        Retrieves a model instance by ID.
        
        Args:
            _id: Record ID
            
        Returns:
            Model instance or None if not found
        """
        query = select(cls.model).where(cls.model.id == _id)
        async with async_session() as session:
            result = await session.execute(query)
        return result.scalars().first()

    @classmethod
    async def delete_by_id(cls, _id: int) -> bool:
        """
        Deletes a record by ID.
        
        Args:
            _id: Record ID
            
        Returns:
            True if deletion was successful
        """
        query = delete(cls.model).where(_id == cls.model.id)
        async with async_session() as session:
            result = await session.execute(query)
            await session.commit()
        return 0 < result.rowcount

    @classmethod
    async def delete_all(cls) -> bool:
        """
        Deletes all records of the model.
        
        Returns:
            True if deletion was successful
        """
        query = delete(cls.model)
        async with async_session() as session:
            result = await session.execute(query)
            await session.commit()
        return 0 < result.rowcount


class BannedIPRepository(BaseRepository):
    model = BannedIP

    @classmethod
    async def create(cls, ban_data: BanCreate) -> Optional[BannedIP]:
        """
        Creates a new banned IP record.
        
        Args:
            ban_data: Ban data
            
        Returns:
            Created BannedIP instance or None if creation failed
        """
        ban_data = BannedIP(**ban_data.model_dump())
        async with async_session() as session:
            session.add(ban_data)
            try:
                await session.flush()
                await session.commit()
            except IntegrityError:
                await session.rollback()
                return
        return ban_data

    @classmethod
    async def create_many(cls, ban_data_list: list[BanCreate]) -> list[BannedIP]:
        """
        Creates multiple banned IP records in a single request.
        
        Args:
            ban_data_list: List of BanCreate objects
            
        Returns:
            List of created BannedIP objects
        """
        if not ban_data_list:
            return []

        ban_objects = [BannedIP(**ban_data.model_dump()) for ban_data in ban_data_list]

        async with async_session() as session:
            session.add_all(ban_objects)
            try:
                await session.flush()
                await session.commit()
            except IntegrityError:
                await session.rollback()
                return []

        return ban_objects

    @classmethod
    async def get_all_expired(cls) -> Sequence[BanResponse]:
        """
        Retrieves all expired banned IP records.
        
        Returns:
            Sequence of expired BannedIP records
        """
        query = select(BannedIP).where(BannedIP.ban_time < datetime.now())
        async with async_session() as session:
            result = await session.execute(query)
        return result.scalars().all()

    @classmethod
    async def delete_ban(cls, ip, node_id) -> int:
        """
        Deletes all expired bans for a specific IP and node.
        
        Args:
            ip: IP address
            node_id: Node ID
            
        Returns:
            Number of deleted records
        """
        query = delete(BannedIP).where(
            BannedIP.ban_time < datetime.now(),
            BannedIP.ip == ip,
            BannedIP.node_id == node_id

        )
        async with async_session() as session:
            result = await session.execute(query)
            await session.commit()
        return result.rowcount

    @classmethod
    async def delete_many(cls, ban_ids: list[int]) -> int:
        """
        Deletes multiple banned IP records in a single request.
        
        Args:
            ban_ids: List of record IDs to delete
            
        Returns:
            Number of deleted records
        """
        if not ban_ids:
            return 0

        query = delete(BannedIP).where(BannedIP.id.in_(ban_ids))

        async with async_session() as session:
            result = await session.execute(query)
            await session.commit()

        return result.rowcount

    @classmethod
    async def get_by_ip(cls, ip: str) -> Optional[BannedIP]:
        """
        Gets a ban record by IP address.
        
        Args:
            ip: IP address
            
        Returns:
            BannedIP record or None if not found
        """
        query = select(BannedIP).where(ip == BannedIP.ip)
        async with async_session() as session:
            result = await session.execute(query)
        return result.scalars().first()


class NodesRepository(BaseRepository):
    model = Node
    # Cache key for all nodes
    ALL_NODES_CACHE_KEY = "nodes:all"
    # Cache TTL in seconds (30 minutes)
    CACHE_TTL = 1800

    @classmethod
    async def _serialize_node(cls, node: Node) -> dict:
        """
        Serializes a node for Redis storage.

        Args:
            node: Node object

        Returns:
            Dictionary with serialized node data
        """
        node_dict = {
            "id": node.id,
            "node_id": node.node_id,
            "node_address": node.node_address,
            "ssh_username": node.ssh_username,
            "ssh_port": node.ssh_port,
            "ssh_password": node.ssh_password,
            "ssh_private_key": node.ssh_private_key,
            "ssh_pk_passphrase": node.ssh_pk_passphrase,
            "is_core": node.is_core,
        }
        # Convert None to "", bool to int 1/0
        return {
            k: ("" if v is None else ("1" if v is True else "0" if v is False else v))
            for k, v in node_dict.items()
        }

    @classmethod
    async def _deserialize_node(cls, node_dict: dict) -> Node:
        """
        Deserializes a node from Redis.
        
        Args:
            node_dict: Dictionary with node data
            
        Returns:
            Node object
        """
        node = Node(
            id=node_dict["id"],
            node_id=node_dict["node_id"],
            node_address=node_dict["node_address"],
            ssh_username=node_dict["ssh_username"],
            ssh_port=node_dict["ssh_port"],
            ssh_password=node_dict["ssh_password"],
            ssh_private_key=node_dict["ssh_private_key"],
            ssh_pk_passphrase=node_dict["ssh_pk_passphrase"],
            is_core=node_dict["is_core"],
        )
        return node

    @classmethod
    async def create(cls, node_data: NodeBase) -> Optional[Node]:
        """
        Creates a new node record.
        
        Args:
            node_data: Node data
            
        Returns:
            Created Node instance or None if creation failed
        """
        node = Node(**node_data.model_dump())
        async with async_session() as session:
            session.add(node)
            try:
                await session.flush()
                await session.commit()

                # Invalidate all nodes cache
                await redis_cli.delete(cls.ALL_NODES_CACHE_KEY)

                # Cache the new node
                node_dict = await cls._serialize_node(node)
                await redis_cli.hset(f"node:{node.id}", mapping=node_dict)
                await redis_cli.expire(f"node:{node.id}", cls.CACHE_TTL)

            except IntegrityError:
                await session.rollback()
                return None
        return node

    @classmethod
    async def get_by_address(cls, address: str) -> Optional[Node]:
        """
        Gets a node by address.
        
        Args:
            address: Node address
            
        Returns:
            Node object or None if not found
        """
        # Check cache
        pipe = redis_cli.pipeline()
        pipe.hgetall(f"node:address:{address}")
        result = await pipe.execute()

        if result[0]:
            # Node found in cache
            node_dict = result[0]
            return await cls._deserialize_node(node_dict)

        # Node not in cache, query from DB
        query = select(Node).where(address == Node.node_address)
        async with async_session() as session:
            result = await session.execute(query)
            node = result.scalars().one_or_none()

        if node:
            # Cache node if found
            node_dict = await cls._serialize_node(node)
            pipe = redis_cli.pipeline()
            pipe.hset(f"node:{node.id}", mapping=node_dict)
            pipe.hset(f"node:address:{address}", mapping=node_dict)
            pipe.expire(f"node:{node.id}", cls.CACHE_TTL)
            pipe.expire(f"node:address:{address}", cls.CACHE_TTL)
            await pipe.execute()

        return node

    @classmethod
    async def get_by_id(cls, _id: int) -> Optional[Node]:
        """
        Gets a node by ID.
        
        Args:
            _id: Node ID
            
        Returns:
            Node object or None if not found
        """
        # Check cache
        pipe = redis_cli.pipeline()
        pipe.hgetall(f"node:{_id}")
        result = await pipe.execute()

        if result[0]:
            # Node found in cache
            node_dict = result[0]
            return await cls._deserialize_node(node_dict)

        # Node not in cache, query from DB
        query = select(cls.model).where(_id == Node.id)
        async with async_session() as session:
            result = await session.execute(query)
            node = result.scalars().one_or_none()

        if node:
            # Cache node if found
            node_dict = await cls._serialize_node(node)
            pipe = redis_cli.pipeline()
            pipe.hset(f"node:{node.id}", mapping=node_dict)
            pipe.hset(f"node:address:{node.node_address}", mapping=node_dict)
            pipe.expire(f"node:{node.id}", cls.CACHE_TTL)
            pipe.expire(f"node:address:{node.node_address}", cls.CACHE_TTL)
            await pipe.execute()

        return node

    @classmethod
    async def get_all_nodes(cls) -> Sequence[NodeResponse]:
        """
        Gets all nodes.
        
        Returns:
            Sequence of all Node objects
        """
        # Check cache
        cached_nodes = await redis_cli.get(cls.ALL_NODES_CACHE_KEY)

        if cached_nodes:
            # Deserialize nodes from cache
            nodes_data = json.loads(cached_nodes)
            return [await cls._deserialize_node(node_data) for node_data in nodes_data]

        # Nodes not in cache, query from DB
        query = select(cls.model).order_by(Node.id)
        async with async_session() as session:
            result = await session.execute(query)
            nodes = result.scalars().all()

        if nodes:
            # Cache all nodes
            nodes_data = [await cls._serialize_node(node) for node in nodes]
            await redis_cli.set(
                cls.ALL_NODES_CACHE_KEY,
                json.dumps(nodes_data),
                ex=cls.CACHE_TTL
            )

        return nodes
