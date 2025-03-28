"""initial migration

Revision ID: 49b483773721
Revises: 
Create Date: 2025-03-26 21:03:52.347958

"""
from typing import Sequence, Union

from fastapi_storages import FileSystemStorage
from fastapi_storages.integrations.sqlalchemy import FileType
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '49b483773721'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None
storage = FileSystemStorage(path="./keys")

def upgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('nodes',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('node_id', sa.Integer(), nullable=False),
    sa.Column('node_address', sa.String(), nullable=False),
    sa.Column('ssh_username', sa.String(), nullable=True),
    sa.Column('ssh_port', sa.Integer(), nullable=True),
    sa.Column('ssh_password', sa.String(), nullable=True),
    sa.Column('ssh_private_key', FileType(storage), nullable=True),
    sa.Column('ssh_pk_passphrase', sa.String(), nullable=True),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('node_address'),
    sa.UniqueConstraint('node_id')
    )
    op.create_table('banned_ips',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('ip', sa.String(), nullable=True),
    sa.Column('email', sa.String(), nullable=True),
    sa.Column('ban_time', sa.DateTime(), nullable=True),
    sa.Column('node_id', sa.Integer(), nullable=False),
    sa.ForeignKeyConstraint(['node_id'], ['nodes.id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('ip', 'node_id', name='uq_ip_node_id')
    )
    # ### end Alembic commands ###


def downgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('banned_ips')
    op.drop_table('nodes')
    # ### end Alembic commands ###
