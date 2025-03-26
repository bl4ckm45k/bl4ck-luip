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


class BannedIPBase(BaseModel):
    ip_address: str = Field(..., examples=["192.168.1.100"])


class NodeBase(BaseModel):
    node_id: int = Field(..., gt=0)
    node_address: str = Field(..., min_length=1)
    ssh_username: Optional[str] = None
    ssh_port: Optional[int] = None
    ssh_password: Optional[str] = None
    ssh_pk_passphrase: Optional[str] = None
    is_core: bool = False


class NodeCreate(NodeBase):
    pass


class NodeUpdate(BaseModel):
    node_address: Optional[str]
    ssh_username: Optional[str]
    ssh_port: Optional[int]
    ssh_password: Optional[str]
    ssh_pk_passphrase: Optional[str]
    is_core: Optional[bool]


class NodeResponse(NodeBase):
    id: int
    banned_ips: List[str] = []
    is_core: bool

    class Config:
        from_attributes = True
