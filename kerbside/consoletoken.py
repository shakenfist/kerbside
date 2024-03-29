import secrets
import string
import time

from shakenfist_utilities import logs

from .config import config
from . import db
from . import util


LOG, _ = logs.setup(__name__, **util.configure_logging())


class TokenFailure(Exception):
    ...


def create_token(source, uuid):
    attempts = 0

    while attempts < 5:
        try:
            # Create a random token id. The maximum length of SPICE passwords
            # doesn't seem to be documented anywhere. The field is 128 bytes in
            # the packet, but you can't just use 128 ASCII characters here.
            alphabet = string.ascii_letters + string.digits
            token = ''.join(secrets.choice(alphabet) for i in range(48))
            session_id = ''.join(secrets.choice(alphabet) for i in range(12))
            now = int(time.time())
            expiry = now + (config.CONSOLE_TOKEN_DURATION * 60)

            # Store the token and return
            db_token = db.add_token(token, session_id, source, uuid, now, expiry)
            LOG.with_fields({
                'source': source,
                'uuid': uuid,
                'session_id': session_id
            }).info('Created authentication token')
            db.add_audit_event(
                source, uuid, session_id, None, None, None,
                'Created authentication token for session.')

            return db_token

        except db.ReusedToken:
            attempts += 1

    raise TokenFailure('Failed to create token after repeated attempts')
