"""connection_id as bigint

Revision ID: 7d1c2f36a7b3
Revises: ad47e96baff6

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '7d1c2f36a7b3'
down_revision = 'ad47e96baff6'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.alter_column(
        'proxychannels', 'connection_id',
        existing_type=sa.Integer(),
        type_=sa.BigInteger())


def downgrade() -> None:
    op.alter_column(
        'proxychannels', 'connection_id',
        existing_type=sa.BigInteger(),
        type_=sa.Integer())
