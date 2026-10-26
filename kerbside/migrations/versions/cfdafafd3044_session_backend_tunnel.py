"""a session's backend tunnel lives on its token row beside its ticket

Revision ID: cfdafafd3044
Revises: d019b0e3c87a

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'cfdafafd3044'
down_revision = 'd019b0e3c87a'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Some sources hand out a console which is only reachable through an
    # HTTP CONNECT proxy, and mint the CONNECT target along with the ticket:
    # the proxy to dial, an opaque host to ask it for, which is itself a
    # signed credential, and the TLS port that host was signed for. Every
    # channel of a session reuses what its first channel minted, so the
    # tunnel is held on the token row with the ticket, and written and
    # cleared with it. All three are NULL for a console reached directly,
    # and no existing row has a tunnel, so there is nothing to fill in.
    op.add_column(
        'consoletokens',
        sa.Column('backend_proxy_uri', sa.String(255), nullable=True))
    op.add_column(
        'consoletokens',
        sa.Column('backend_connect_host', sa.String(255), nullable=True))
    op.add_column(
        'consoletokens',
        sa.Column('backend_port', sa.Integer, nullable=True))


def downgrade() -> None:
    # Tunnels minted for sessions go with the columns. The tickets stay: a
    # daemon from before this revision has no source which mints a tunnel.
    op.drop_column('consoletokens', 'backend_port')
    op.drop_column('consoletokens', 'backend_connect_host')
    op.drop_column('consoletokens', 'backend_proxy_uri')
