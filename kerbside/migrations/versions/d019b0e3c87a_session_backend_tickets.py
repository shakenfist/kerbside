"""a session's backend console ticket lives on its token row

Revision ID: d019b0e3c87a
Revises: 3b8d5f1a6c92

"""
from alembic import context
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'd019b0e3c87a'
down_revision = '3b8d5f1a6c92'
branch_labels = None
depends_on = None


# Selects the oVirt consoles which still hold a ticket.
_OVIRT_TICKETS = (
    'WHERE ticket != \'\' '
    'AND source IN (SELECT name FROM sources WHERE type = \'ovirt\')')


def upgrade() -> None:
    # A source which mints console tickets mints one when the first channel
    # of a session connects, and every channel of that session reuses it,
    # whichever proxy node it lands on. The shared database is the only
    # thing every node can reach, so the ticket is held on the session's
    # token row until it expires. backend_ticket_expires is whole epoch
    # seconds, like expires on the same row, so Integer does not lose
    # precision the way a FLOAT time.time() column does (issue #533).
    op.add_column(
        'consoletokens',
        sa.Column('backend_ticket', sa.String(255), nullable=True))
    op.add_column(
        'consoletokens',
        sa.Column('backend_ticket_expires', sa.Integer, nullable=True))

    # oVirt tickets used to be minted per .vv request and stored on the
    # console row, shared by every session of the console, for the two hours
    # the engine grants by default. Nothing reads them from there any more,
    # so they are live passwords with no purpose: clear them. Static sources
    # keep theirs, which is operator configuration rather than a minted
    # credential. Rendered offline there is nothing to count.
    if not context.is_offline_mode():
        consoles = op.get_bind().execute(
            sa.text('SELECT COUNT(*) FROM consoles ' + _OVIRT_TICKETS)
        ).scalar()
        print('Upgrade clears the stored ticket of %d oVirt consoles; oVirt '
              'tickets are now minted when a channel connects' % consoles)
    op.execute('UPDATE consoles SET ticket = \'\' ' + _OVIRT_TICKETS)


def downgrade() -> None:
    # The cleared oVirt tickets stay empty: an older daemon mints a fresh
    # one into the console row on the next .vv request, so nothing needs
    # putting back. Tickets minted for sessions go with the columns.
    op.drop_column('consoletokens', 'backend_ticket_expires')
    op.drop_column('consoletokens', 'backend_ticket')
