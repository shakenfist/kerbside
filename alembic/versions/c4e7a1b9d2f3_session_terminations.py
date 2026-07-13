"""session terminations intent table

Revision ID: c4e7a1b9d2f3
Revises: 9a3f1c7b2e40

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'c4e7a1b9d2f3'
down_revision = '9a3f1c7b2e40'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Kerbside can run distributed: the REST API and the proxy processes may be
    # on different machines, and a load balancer can spread one session's
    # channels across multiple proxy nodes. The database is therefore the only
    # shared bus between the API and the proxies. The API records a session
    # termination as an explicit, session-scoped intent row here (keeping the
    # existing token expire/remove, which blocks NEW connections); each proxy
    # node's daemon polls this table for the sessions it holds live channels
    # for and pushes a TerminateSession event to its local proxy over the local
    # gRPC/UDS control stream, dropping the IN-FLIGHT connections. A TTL reaper
    # deletes rows once every node has had time to poll (the Rust side is
    # idempotent, so a late or duplicate event is a no-op).
    #
    # session_id matches the width of consoletokens.session_id / the session_id
    # columns elsewhere. requested_at is a time.time() float.
    op.create_table(
        'session_terminations',
        sa.Column('session_id', sa.String(12)),
        sa.Column('requested_at', sa.Float),
        sa.Column('reason', sa.String(255), nullable=True),
        sa.PrimaryKeyConstraint('session_id')
    )


def downgrade() -> None:
    op.drop_table('session_terminations')
