"""auditevents pid as string

Revision ID: e1a4c7d2f9b6
Revises: c4e7a1b9d2f3

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'e1a4c7d2f9b6'
down_revision = 'c4e7a1b9d2f3'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # auditevents.pid was created as INTEGER by the initial schema, back when
    # only the Python proxy wrote it (an OS process id). The gRPC/Rust path
    # writes a per-connection connection_ref (a UUID string) instead, and the
    # ORM model was updated to String to accommodate both. The column type was
    # never migrated, so MySQL/MariaDB (which, unlike SQLite, enforces declared
    # column types) rejects the UUID with "Data truncated for column 'pid'",
    # failing every AuthorizeConnection audit write. Widen the column to a
    # string so it can hold either identity, matching proxychannels.connection_ref.
    op.alter_column(
        'auditevents', 'pid',
        existing_type=sa.Integer(), type_=sa.String(255),
        existing_nullable=True)


def downgrade() -> None:
    # Rows written by the gRPC path hold a non-numeric connection_ref that
    # cannot cast back to INTEGER (strict mode would error on the ALTER). Null
    # those out first so the type change is deterministic; audit rows are
    # preserved (unlike proxychannels, which is ephemeral), only the opaque pid
    # tag is lost for gRPC-written rows.
    op.execute(
        "UPDATE auditevents SET pid = NULL WHERE pid REGEXP '[^0-9]'")
    op.alter_column(
        'auditevents', 'pid',
        existing_type=sa.String(255), type_=sa.Integer(),
        existing_nullable=True)
