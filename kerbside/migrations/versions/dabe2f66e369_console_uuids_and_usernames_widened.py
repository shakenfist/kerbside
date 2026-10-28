"""console identifiers and source usernames widened

Revision ID: dabe2f66e369
Revises: cfdafafd3044

"""
from alembic import context
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'dabe2f66e369'
down_revision = 'cfdafafd3044'
branch_labels = None
depends_on = None


# Every table holding a console's identifier in a column named uuid, and
# whether that column may be NULL. It may not where it is part of the
# primary key, and MODIFY restates nullability, so it has to be given.
_UUID_COLUMNS = (
    ('consoles', False),
    ('consoletokens', True),
    ('auditevents', False),
)

# The widths the initial schema gave the columns, which the downgrade
# restores, and the width this revision gives them.
_OLD_UUID_LENGTH = 36
_OLD_USERNAME_LENGTH = 50
_NEW_LENGTH = 255


def _resize(uuid_from, uuid_to, username_from, username_to):
    # MariaDB and MySQL refuse to change a column a foreign key names, even
    # only to widen it ("Cannot change column 'uuid': used in a foreign key
    # constraint", errors 1832 and 1833 on MariaDB 11.8), so a token's
    # reference to its console is dropped around the change and put back as
    # 3b8d5f1a6c92 made it. Its index on (source, uuid) stays, and the new
    # constraint uses it again. Changing a column's width changes none of the
    # pairs the constraint held, and adding it back checks every row, so a
    # token naming no console which was written while it was gone would fail
    # the migration rather than be let in.
    op.drop_constraint(
        'fk_consoletokens_console', 'consoletokens', type_='foreignkey')
    for table, nullable in _UUID_COLUMNS:
        op.alter_column(
            table, 'uuid',
            existing_type=sa.String(uuid_from), type_=sa.String(uuid_to),
            existing_nullable=nullable)
    op.create_foreign_key(
        'fk_consoletokens_console', 'consoletokens', 'consoles',
        ['source', 'uuid'], ['source', 'uuid'],
        onupdate='CASCADE', ondelete='CASCADE')

    op.alter_column(
        'sources', 'username',
        existing_type=sa.String(username_from), type_=sa.String(username_to),
        existing_nullable=True)


def upgrade() -> None:
    # A console's identifier is whatever its source names it by, but the
    # initial schema sized every column holding one for a 36 character UUID.
    # A Proxmox VE console is named '<vmid>-<SMBIOS UUID>', 38 to 46
    # characters. MariaDB in strict mode refuses it ("Data too long"), and
    # without strict mode cuts it to 36, so that the console could never be
    # minted for and two VMs could share one row. consoles, consoletokens and
    # auditevents all hold it, and are widened together to 255, the width of
    # the source each sits beside.
    #
    # sources.username is widened in the same pass. A Proxmox VE source
    # authenticates with an API token, whose ID, 'user@realm!tokenid', is
    # stored there and can run past the initial schema's 50 characters.
    #
    # Widening a VARCHAR changes no value, so there is no data to fix up. The
    # keys stay inside InnoDB's 3072 byte limit at utf8mb4's four bytes a
    # character: consoles (source, uuid), and the tokens' index on the same
    # pair, are 2040 bytes, and auditevents (source, uuid, timestamp) 2048.
    # sources.username is not indexed.
    _resize(_OLD_UUID_LENGTH, _NEW_LENGTH,
            _OLD_USERNAME_LENGTH, _NEW_LENGTH)


def downgrade() -> None:
    # Narrowing the columns again would cut whatever no longer fits, or in
    # strict mode fail part way through. The earlier schema has no room for
    # a console named past 36 characters, so such a console goes, with its
    # tokens and its audit events. Nor has it room for a username past 50
    # characters, so such a source goes, with its consoles and their tokens;
    # a daemon from before this revision could have used none of them, and
    # the source cannot be added back until its username is shortened.
    # Tokens and consoles are deleted explicitly rather than left to the
    # cascades, and audit events of a deleted source's shorter identifiers
    # are kept, as they would be had the source been removed.
    long_usernames = (
        'SELECT name FROM sources WHERE CHAR_LENGTH(username) > %d'
        % _OLD_USERNAME_LENGTH)
    tokens = (
        'FROM consoletokens WHERE CHAR_LENGTH(uuid) > %d OR source IN (%s)'
        % (_OLD_UUID_LENGTH, long_usernames))
    consoles = (
        'FROM consoles WHERE CHAR_LENGTH(uuid) > %d OR source IN (%s)'
        % (_OLD_UUID_LENGTH, long_usernames))
    events = (
        'FROM auditevents WHERE CHAR_LENGTH(uuid) > %d' % _OLD_UUID_LENGTH)
    sources = (
        'FROM sources WHERE CHAR_LENGTH(username) > %d'
        % _OLD_USERNAME_LENGTH)

    # Said out loud because it is data loss, and an operator rolling back
    # otherwise has no trace of the consoles, sessions and history it cost
    # them. Rendered offline there is nothing to count, and the deletes are
    # in the script for whoever runs it to read.
    if not context.is_offline_mode():
        bind = op.get_bind()
        counts = [
            bind.execute(sa.text('SELECT COUNT(*) ' + rows)).scalar()
            for rows in (consoles, tokens, events, sources)]
        print('Downgrade drops %d consoles named by more than %d characters '
              'or from a source whose username is longer than %d, their %d '
              'console tokens, %d audit events for consoles named by more '
              'than %d characters, and %d sources whose username is longer '
              'than %d characters; the earlier schema cannot hold them'
              % (counts[0], _OLD_UUID_LENGTH, _OLD_USERNAME_LENGTH, counts[1],
                 counts[2], _OLD_UUID_LENGTH, counts[3],
                 _OLD_USERNAME_LENGTH))
    op.execute('DELETE ' + tokens)
    op.execute('DELETE ' + consoles)
    op.execute('DELETE ' + events)
    op.execute('DELETE ' + sources)

    _resize(_NEW_LENGTH, _OLD_UUID_LENGTH,
            _NEW_LENGTH, _OLD_USERNAME_LENGTH)
