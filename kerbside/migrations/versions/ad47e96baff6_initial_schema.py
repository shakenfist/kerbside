"""Create the initial schema.

Revision ID: ad47e96baff6
Revises:

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy import text
from sqlalchemy.dialects.mysql import DATETIME


# revision identifiers, used by Alembic.
revision = 'ad47e96baff6'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'sources',
        sa.Column('name', sa.String(255), unique=True),
        sa.Column('type', sa.String(20)),
        sa.Column('last_seen', sa.DateTime, index=True),
        sa.Column('seen_by', sa.String(255)),
        sa.Column('errored', sa.Boolean),
        sa.Column('url', sa.String(1024)),
        sa.Column('ca_cert', sa.Text),
        sa.Column('username', sa.String(50)),
        sa.Column('password', sa.String(255)),

        # OpenStack specific values
        sa.Column('project_name', sa.String(255)),
        sa.Column('user_domain_id', sa.String(255)),
        sa.Column('project_domain_id', sa.String(255)),
        sa.Column('flavor', sa.String(255)),

        sa.PrimaryKeyConstraint('name')
    )

    op.create_table(
        'consoles',
        sa.Column('uuid', sa.String(36)),
        sa.Column('source', sa.String(255),
                  sa.ForeignKey('sources.name', onupdate='CASCADE', ondelete='CASCADE'),
                  index=True),
        sa.Column('discovered', sa.DateTime),
        sa.Column('hypervisor', sa.String(255)),
        sa.Column('hypervisor_ip', sa.String(15)),
        sa.Column('insecure_port', sa.Integer),
        sa.Column('secure_port', sa.Integer),
        sa.Column('name', sa.String(255)),
        sa.Column('host_subject', sa.String(1024)),
        sa.Column('ticket', sa.String(255)),
        sa.PrimaryKeyConstraint('uuid')
    )

    op.create_table(
        'consoletokens',
        sa.Column('token', sa.String(128)),
        sa.Column('session_id', sa.String(12), index=True),
        sa.Column('uuid', sa.String(36),
                  sa.ForeignKey('consoles.uuid', onupdate='CASCADE', ondelete='CASCADE'),
                  index=True),
        sa.Column('source', sa.String(255), index=True),
        sa.Column('created', sa.Integer),
        sa.Column('expires', sa.Integer, index=True),
        sa.PrimaryKeyConstraint('token')
    )

    op.create_table(
        'proxychannels',
        sa.Column('node', sa.String(255)),
        sa.Column('pid', sa.Integer),
        sa.Column('created', sa.DateTime),
        sa.Column('client_ip', sa.String(15)),
        sa.Column('client_port', sa.Integer),
        sa.Column('connection_id', sa.Integer),
        sa.Column('channel_type', sa.String(255)),
        sa.Column('channel_id', sa.Integer),
        sa.Column('session_id', sa.String(12),
                  sa.ForeignKey('consoletokens.session_id', onupdate='CASCADE', ondelete='CASCADE')),
        sa.PrimaryKeyConstraint('node', 'pid')
    )

    op.create_table(
        'auditevents',
        sa.Column('source', sa.String(255)),
        sa.Column('uuid', sa.String(36)),
        sa.Column('session_id', sa.String(12)),
        sa.Column('channel', sa.String(30)),
        sa.Column('timestamp', DATETIME(fsp=6), server_default=text('CURRENT_TIMESTAMP(6)')),
        sa.Column('node', sa.String(255)),
        sa.Column('pid', sa.Integer),
        sa.Column('message', sa.Text),
        sa.PrimaryKeyConstraint('source', 'uuid', 'timestamp')
    )


def downgrade():
    op.drop_table('auditevents')
    op.drop_table('proxychannels')
    op.drop_table('consoletokens')
    op.drop_table('consoles')
    op.drop_table('sources')
