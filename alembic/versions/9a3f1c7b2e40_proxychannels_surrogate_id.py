"""proxychannels surrogate id primary key

Revision ID: 9a3f1c7b2e40
Revises: bb26023f0c98

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '9a3f1c7b2e40'
down_revision = 'bb26023f0c98'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # proxychannels was keyed by the composite primary key (node, pid). The
    # Rust proxy is a single process with no per-connection pid, so switch to
    # a surrogate autoincrement id primary key. node/pid are kept (now
    # nullable) for the Python proxy and its pid-matching reaper, and a
    # nullable connection_ref is added for the gRPC/Rust path.
    #
    # On MySQL/MariaDB an AUTO_INCREMENT column must be a key at all times, so
    # dropping the composite primary key and adding the id column as the new
    # primary key must happen in a single ALTER statement. Adding an
    # AUTO_INCREMENT PRIMARY KEY column also back-numbers any existing rows.
    op.execute(
        'ALTER TABLE proxychannels '
        'DROP PRIMARY KEY, '
        'ADD COLUMN id INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY FIRST')

    op.alter_column(
        'proxychannels', 'node',
        existing_type=sa.String(255), nullable=True)
    op.alter_column(
        'proxychannels', 'pid',
        existing_type=sa.Integer(), nullable=True)

    op.add_column(
        'proxychannels',
        sa.Column('connection_ref', sa.String(255), nullable=True))

    # client_ip is declared Integer in the ORM model but was created as
    # String(15) by the initial migration and the proxy writes a host string.
    # Reconcile the model to a string and widen the column so it can hold
    # hostnames as well as IPv4/IPv6 literals.
    op.alter_column(
        'proxychannels', 'client_ip',
        existing_type=sa.String(15), type_=sa.String(255),
        existing_nullable=True)


def downgrade() -> None:
    op.alter_column(
        'proxychannels', 'client_ip',
        existing_type=sa.String(255), type_=sa.String(15),
        existing_nullable=True)

    op.drop_column('proxychannels', 'connection_ref')

    op.alter_column(
        'proxychannels', 'pid',
        existing_type=sa.Integer(), nullable=False)
    op.alter_column(
        'proxychannels', 'node',
        existing_type=sa.String(255), nullable=False)

    # Drop the surrogate id (and its AUTO_INCREMENT) and restore the composite
    # (node, pid) primary key in a single statement, since an AUTO_INCREMENT
    # column may not exist without being part of a key.
    op.execute(
        'ALTER TABLE proxychannels '
        'DROP PRIMARY KEY, '
        'DROP COLUMN id, '
        'ADD PRIMARY KEY (node, pid)')
