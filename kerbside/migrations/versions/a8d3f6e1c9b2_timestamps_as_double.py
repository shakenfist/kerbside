"""time.time() columns as double precision

Revision ID: a8d3f6e1c9b2
Revises: cdb5c3529858

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'a8d3f6e1c9b2'
down_revision = 'cdb5c3529858'
branch_labels = None
depends_on = None


# Every column holding a time.time() float. They were created as sa.Float,
# which MySQL and MariaDB store as a single-precision FLOAT: a 24-bit mantissa
# can only represent current epoch times to the nearest 128 seconds, and
# MariaDB reads one back rounded to six significant digits, so a value could
# come back more than an hour out. The jti reaper could then drop a jti while
# its token was still valid and replayable, and a fetch time could not be
# compared with the clock at all (issue #533). SQLite stores both types as an
# eight-byte REAL, so nothing changes there.
_COLUMNS = [
    ('sf_token_jtis', 'expiry'),
    ('sf_token_keys', 'fetched_at'),
    ('session_terminations', 'requested_at'),
]


def upgrade() -> None:
    # Values already stored stay rounded; the jti and key rows are rewritten
    # within a token lifetime and a key refresh respectively, and termination
    # rows are reaped on a TTL, so no backfill is needed.
    for table, column in _COLUMNS:
        op.alter_column(
            table, column,
            existing_type=sa.Float(), type_=sa.Double(),
            existing_nullable=True)


def downgrade() -> None:
    for table, column in _COLUMNS:
        op.alter_column(
            table, column,
            existing_type=sa.Double(), type_=sa.Float(),
            existing_nullable=True)
