from datetime import datetime
from typing import Optional, Sequence

from sqlalchemy import select, delete
from sqlalchemy.exc import IntegrityError

from .database import async_session
from .models import BannedIP, Node
from .schemas import BanCreate, BanResponse, NodeBase


class BaseRepository:
    model = None

    @classmethod
    async def get_all(cls):
        query = select(cls.model)
        async with async_session() as session:
            result = await session.execute(query)
        return result.scalars().all()

    @classmethod
    async def get_by_id(cls, _id: int) -> Optional[object]:
        query = select(cls.model).where(cls.model.id == _id)
        async with async_session() as session:
            result = await session.execute(query)
        return result.scalars().first()

    @classmethod
    async def delete_by_id(cls, _id: int) -> bool:
        query = delete(cls.model).where(_id == cls.model.id)
        async with async_session() as session:
            result = await session.execute(query)
            await session.commit()
        return 0 < result.rowcount

    @classmethod
    async def delete_all(cls) -> bool:
        query = delete(cls.model)
        async with async_session() as session:
            result = await session.execute(query)
            await session.commit()
        return 0 < result.rowcount

class BannedIPRepository(BaseRepository):
    model = BannedIP

    @classmethod
    async def create(cls, ban_data: BanCreate) -> Optional[BannedIP]:
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
    async def get_all_expired(cls) -> Sequence[BanResponse]:
        query = select(BannedIP).where(BannedIP.ban_time < datetime.now())
        async with async_session() as session:
            result = await session.execute(query)
        return result.scalars().all()

    @classmethod
    async def delete_ban(cls, ip, node_id) -> int:
        """Удаляет все устаревшие баны"""
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
    async def get_by_ip(cls, ip: str) -> Optional[BannedIP]:
        """Получает бан по IP-адресу"""
        query = select(BannedIP).where(ip == BannedIP.ip)
        async with async_session() as session:
            result = await session.execute(query)
        return result.scalars().first()


class NodesRepository(BaseRepository):
    model = Node

    @classmethod
    async def create(cls, node_data: NodeBase) -> Optional[Node]:
        """Создаёт новую запись узла"""
        node = Node(**node_data.model_dump())
        async with async_session() as session:
            session.add(node)
            try:
                await session.flush()
                await session.commit()
            except IntegrityError:
                await session.rollback()
                return None
        return node

    @classmethod
    async def get_by_address(cls, address: str) -> Optional[Node]:
        """Получает узел по имени"""
        query = select(Node).where(address == Node.node_address)
        async with async_session() as session:
            result = await session.execute(query)
        return result.scalars().one_or_none()

    @classmethod
    async def get_by_id(cls, _id: int) -> Optional[Node]:
        query = select(cls.model).where(_id == Node.id)
        async with async_session() as session:
            result = await session.execute(query)
        return result.scalars().one_or_none()

    @classmethod
    async def get_all_nodes(cls) -> Sequence[Node]:
        query = select(cls.model).order_by(Node.id)
        async with async_session() as session:
            result = await session.execute(query)
        return result.scalars().all()
