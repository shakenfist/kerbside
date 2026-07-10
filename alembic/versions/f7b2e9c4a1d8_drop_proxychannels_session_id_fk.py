"""drop proxychannels.session_id -> consoletokens foreign key

Revision ID: f7b2e9c4a1d8
Revises: e1a4c7d2f9b6

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'f7b2e9c4a1d8'
down_revision = 'e1a4c7d2f9b6'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # proxychannels.session_id was created with a
    # ForeignKey('consoletokens.session_id', ondelete='CASCADE') by the initial
    # schema, back when the Python proxy owned both tables. proxychannels is now
    # the Rust proxy's independent live-connection bookkeeping (created,
    # updated and removed by the proxy over gRPC), and the ORM model already
    # carries no ForeignKey on the column -- but the constraint was never
    # dropped from the database.
    #
    # The cascade actively breaks in-flight termination. terminate_session()
    # deletes the console token (to block NEW connections) before recording the
    # termination intent; ON DELETE CASCADE then deletes the live proxychannels
    # rows for that session. The per-node daemon computes "sessions to drop" as
    # (session_terminations INTERSECT this node's live proxychannels), so with
    # the channels gone the intersection is empty and no TerminateSession is
    # ever pushed to the proxy -- the in-flight connection is never dropped.
    #
    # SQLite defaults foreign_keys OFF, so the cascade never fired there (the
    # oVirt CI lane passed); MySQL/MariaDB enforces it (the direct-qemu and
    # OpenStack/Kolla lanes hung until the 30s terminate timeout). Drop the
    # constraint to match the model and decouple the two lifetimes.
    bind = op.get_bind()
    if bind.dialect.name == 'sqlite':
        # SQLite never enforced this FK and cannot ALTER-drop a named
        # constraint; the model carries no FK, so there is nothing to do.
        return
    insp = sa.inspect(bind)
    for fk in insp.get_foreign_keys('proxychannels'):
        if (fk['referred_table'] == 'consoletokens'
                and 'session_id' in fk['constrained_columns']):
            op.drop_constraint(fk['name'], 'proxychannels', type_='foreignkey')


def downgrade() -> None:
    # Recreate the cascade FK. Any proxychannels.session_id with no matching
    # consoletokens row (e.g. a live channel whose token was deleted -- exactly
    # what the upgrade enables) would violate the restored constraint, so null
    # those out first. Skipped on SQLite, which never had the constraint.
    bind = op.get_bind()
    if bind.dialect.name == 'sqlite':
        return
    op.execute(
        'UPDATE proxychannels SET session_id = NULL WHERE session_id NOT IN '
        '(SELECT session_id FROM consoletokens)')
    op.create_foreign_key(
        'proxychannels_ibfk_1', 'proxychannels', 'consoletokens',
        ['session_id'], ['session_id'],
        onupdate='CASCADE', ondelete='CASCADE')
