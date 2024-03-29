"""Sources can be deleted

Revision ID: 5c8101ff14d7
Revises: 7d1c2f36a7b3

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '5c8101ff14d7'
down_revision = '7d1c2f36a7b3'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column('sources', sa.Column('deleted', sa.Boolean()))


def downgrade() -> None:
    op.drop_column('sources', 'deleted')
