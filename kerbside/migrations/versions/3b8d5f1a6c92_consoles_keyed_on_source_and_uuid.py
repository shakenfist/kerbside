"""key consoles on (source, uuid)

Revision ID: 3b8d5f1a6c92
Revises: cdb5c3529858

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '3b8d5f1a6c92'
down_revision = 'cdb5c3529858'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # consoles was keyed on uuid alone, where every other table naming a
    # console keys on (source, uuid). Two sources publishing the same
    # identifier -- a hand written static entry is the practical case --
    # shared one row: the second overwrote the first's hypervisor, ports
    # and pinned subject but not its source, and either retiring the
    # identifier deleted it for both (issue #468).
    #
    # Existing rows cannot collide on the new key, since the old one was
    # stricter. A row with no source could never be looked up by the new
    # one, and every writer has always supplied a source, so any such
    # row is debris; the next maintenance pass rediscovers anything real.
    op.execute('DELETE FROM consoles WHERE source IS NULL')

    # consoletokens.uuid references consoles.uuid with a cascading delete,
    # which on the composite key would delete one source's tokens when
    # another source retires the same identifier. It is replaced by a
    # reference to the pair. A token whose pair no longer names a console
    # is unusable already (authorisation looks the console up by the
    # same pair) and would violate the new constraint, so it goes.
    op.execute(
        'DELETE FROM consoletokens WHERE NOT EXISTS ('
        'SELECT 1 FROM consoles WHERE consoles.source = consoletokens.source '
        'AND consoles.uuid = consoletokens.uuid)')

    # MySQL and MariaDB only, like the initial schema this revises,
    # whose CURRENT_TIMESTAMP(6) default SQLite cannot create.
    insp = sa.inspect(op.get_bind())
    for fk in insp.get_foreign_keys('consoletokens'):
        if fk['referred_table'] == 'consoles':
            op.drop_constraint(fk['name'], 'consoletokens', type_='foreignkey')
    op.alter_column(
        'consoles', 'source',
        existing_type=sa.String(255), nullable=False)
    op.execute(
        'ALTER TABLE consoles DROP PRIMARY KEY, ADD PRIMARY KEY (source, uuid)')
    op.create_foreign_key(
        'fk_consoletokens_console', 'consoletokens', 'consoles',
        ['source', 'uuid'], ['source', 'uuid'],
        onupdate='CASCADE', ondelete='CASCADE')


def downgrade() -> None:
    # The single column key cannot hold an identifier two sources share.
    # Which source should keep it is not a question the data answers, so
    # every shared identifier is dropped; the next maintenance pass puts
    # one of them back, with the sharing this migration removed. Their
    # tokens are deleted first, explicitly, rather than left to the
    # cascade.
    shared = (
        'SELECT uuid FROM (SELECT uuid FROM consoles GROUP BY uuid '
        'HAVING COUNT(*) > 1) AS shared')
    op.execute('DELETE FROM consoletokens WHERE uuid IN (%s)' % shared)
    op.execute('DELETE FROM consoles WHERE uuid IN (%s)' % shared)

    op.drop_constraint(
        'fk_consoletokens_console', 'consoletokens', type_='foreignkey')
    op.execute('ALTER TABLE consoles DROP PRIMARY KEY, ADD PRIMARY KEY (uuid)')
    op.alter_column(
        'consoles', 'source',
        existing_type=sa.String(255), nullable=True)
    op.create_foreign_key(
        'consoletokens_ibfk_1', 'consoletokens', 'consoles',
        ['uuid'], ['uuid'], onupdate='CASCADE', ondelete='CASCADE')
