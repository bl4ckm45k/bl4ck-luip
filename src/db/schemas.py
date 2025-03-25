from datetime import datetime
from typing import Optional, List

from pydantic import BaseModel, Field


class BanCreate(BaseModel):
    ip: str
    email: str
    ban_time: Optional[datetime] = None
    node_id: int


class BanResponse(BaseModel):
    id: int
    ip: str
    email: str
    ban_time: datetime
    node_id: int

    class Config:
        from_attributes = True


class NodeBase(BaseModel):
    node_id: int = Field(..., examples=[1])
    node_address: str = Field(..., examples=["192.168.1.1"])


class NodeUpdate(BaseModel):
    node_address: Optional[str] = None
    ssh_username: Optional[str] = None
    ssh_port: Optional[int] = None
    ssh_password: Optional[str] = None
    ssh_private_key: Optional[str] = None
    ssh_pk_passphrase: Optional[str] = None


class BannedIPBase(BaseModel):
    ip_address: str = Field(..., examples=["192.168.1.100"])


class NodeResponse(NodeBase):
    id: int
    banned_ips: List[BannedIPBase] = []

    class Config:
        from_attributes = True
