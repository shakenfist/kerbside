"""sf token tables

Revision ID: cdb5c3529858
Revises: f7b2e9c4a1d8

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'cdb5c3529858'
down_revision = 'f7b2e9c4a1d8'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Offline verification of Shaken Fist's Ed25519-signed VDI console JWTs
    # (phase 5 of the VDI console tokens plan) needs two small caches in the
    # shared DB -- kerbside's DB-only-IPC rule means the API process cannot
    # reach the ephemeral, maintenance-loop-owned source objects directly.
    #
    # sf_token_jtis enforces single-use tokens: the jti (a uuid4 hex) is
    # recorded once a token verifies, so a replayed token is rejected.
    # expiry mirrors the token's own exp claim (a time.time()-style float) so
    # the reaper can drop rows once they can no longer be replayed anyway.
    op.create_table(
        'sf_token_jtis',
        sa.Column('jti', sa.String(32)),
        sa.Column('expiry', sa.Float),
        sa.PrimaryKeyConstraint('jti')
    )

    # sf_token_keys caches each shakenfist source's signing public keys
    # (Shaken Fist's public_view payload, verbatim JSON) so the exchange
    # endpoint never calls Shaken Fist on the hot path -- only a cache miss
    # on an unknown kid triggers a refetch. source matches sources.name
    # (no FK: sources are reloaded from YAML by the maintenance loop, not a
    # stable referenced row). fetched_at is a time.time() float.
    op.create_table(
        'sf_token_keys',
        sa.Column('source', sa.String(255)),
        sa.Column('keys_json', sa.Text),
        sa.Column('fetched_at', sa.Float),
        sa.PrimaryKeyConstraint('source')
    )


def downgrade() -> None:
    op.drop_table('sf_token_keys')
    op.drop_table('sf_token_jtis')
