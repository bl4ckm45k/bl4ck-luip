from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, UniqueConstraint, LargeBinary
from sqlalchemy.orm import declarative_base, relationship
from fastapi_storages import FileSystemStorage
from fastapi_storages.integrations.sqlalchemy import FileType
from utils.private_data import decrypt_password, encrypt_password
storage = FileSystemStorage(path="./keys")
Base = declarative_base()


class Node(Base):
    __tablename__ = 'nodes'

    id = Column(Integer, primary_key=True)
    node_id = Column(Integer, unique=True, nullable=False)
    node_address = Column(String, unique=True, nullable=False)
    ssh_username = Column(String)
    ssh_port = Column(Integer)
    ssh_password = Column(String)
    ssh_private_key = Column(FileType(storage=storage))
    ssh_pk_passphrase = Column(String)

    # OneToMany
    banned_ips = relationship("BannedIP", back_populates="node")

    def __repr__(self):
        return f'ID: {self.node_id} | Node Address: {self.node_address}'


class BannedIP(Base):
    __tablename__ = 'banned_ips'

    id = Column(Integer, primary_key=True)
    ip = Column(String)
    email = Column(String)
    ban_time = Column(DateTime)
    node_id = Column(Integer, ForeignKey('nodes.id'), nullable=False)  # Правильное имя поля

    node = relationship("Node", back_populates="banned_ips")

    __table_args__ = (
        UniqueConstraint('ip', 'node_id', name='uq_ip_node_id'),  # Исправил имя уникального ограничения
    )
