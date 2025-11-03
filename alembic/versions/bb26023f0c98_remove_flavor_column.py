"""Remove flavor column

Revision ID: bb26023f0c98
Revises: 5c8101ff14d7

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'bb26023f0c98'
down_revision = '5c8101ff14d7'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.drop_column('sources', 'flavor')


def downgrade() -> None:
    op.add_column('sources', sa.Column('flavor', sa.String(255)))
